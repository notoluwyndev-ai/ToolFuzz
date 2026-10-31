# tools/*.json — esquema de herramientas

`server.py` escanea esta carpeta al atender cada petición a `GET /api/tools`
(y antes de ejecutar un comando). **No hay ninguna lista de binarios,
comandos o categorías escrita en el código.** Para añadir, cambiar o quitar
una herramienta del panel basta con crear, editar o borrar su archivo
`.json` aquí — no hace falta tocar `server.py` ni `index.html`.

Usa `plantilla.json` como punto de partida. Un archivo con errores (JSON
inválido, campos obligatorios ausentes, id que no coincide con el nombre de
archivo, etc.) simplemente se omite del catálogo; el servidor registra un
aviso (`logger.warning`) explicando por qué, y el resto de herramientas
siguen funcionando con normalidad.

## Reglas generales

- El nombre del archivo debe ser `<id>.json`, y ese `id` debe coincidir
  exactamente con el campo `"id"` de dentro. `id` solo admite
  `[a-zA-Z0-9_-]`, máximo 40 caracteres.
- `id` duplicados entre dos archivos: se queda el primero en orden
  alfabético y se descarta el resto.
- El binario (`"binary"`, o el `"entrypoint"` si lo hay) debe existir en el
  `PATH` del sistema para que la herramienta aparezca como ejecutable; si
  no, el panel la muestra marcada como "binario no instalado" pero sigue
  listada.

## Campos de nivel herramienta

| Campo         | Tipo   | Obligatorio | Descripción                                                                 |
|---------------|--------|:-----------:|-------------------------------------------------------------------------------|
| `id`          | string | sí          | Identificador único; debe coincidir con el nombre de archivo.                |
| `name`        | string | sí          | Nombre visible en la tarjeta y cabecera.                                     |
| `icon`        | string | sí          | Un emoji o carácter corto para el icono.                                     |
| `description` | string | sí          | Descripción breve, visible en la tarjeta y cabecera.                        |
| `binary`      | string | sí          | Ejecutable a lanzar (se resuelve con `shutil.which`, nunca vía shell).       |
| `category`    | string | no          | Clave libre para agrupar en el panel (p. ej. `network`, `webfuzz`, `osint`, `vuln`, `creds`). Si se omite o no es texto, se usa `other`. Una categoría nueva aparece sola en el panel, sin tocar código. |
| `entrypoint`  | string | no          | Script relativo a la carpeta local de scripts de ToolFuzz, lanzado como primer argumento del binario (p. ej. `whatweb.json` usa `binary: "ruby"` + este campo). Debe quedar dentro de esa carpeta. |
| `commands`    | array  | sí          | Lista no vacía de comandos (ver abajo). Un comando inválido se omite; si no queda ninguno válido, la herramienta entera se omite. |

## Campos de cada comando (`commands[]`)

| Campo             | Tipo    | Obligatorio | Descripción                                                               |
|-------------------|---------|:-----------:|-----------------------------------------------------------------------------|
| `id`              | string  | sí          | Identificador único dentro de la herramienta (mismas reglas que el `id` de arriba). |
| `label`           | string  | sí          | Texto de la pestaña (1–160 caracteres). Puede incluir `{campo}` para interpolar valores en vivo. |
| `args`            | array[string] | sí    | Argumentos del binario, en orden, como lista (nunca una cadena de shell). Cada elemento puede contener `{campo}` para sustituir el valor de un `fields[].id`. |
| `fields`          | array   | no          | Campos de entrada del formulario (ver abajo). Vacío = comando sin parámetros. |
| `danger`          | string  | no          | Riesgo informativo (`low`/`medium`/`high`); `high` requiere confirmación explícita en la interfaz antes de ejecutar. |
| `runtime_seconds` | integer | no          | Tiempo máximo antes de cancelar el proceso. Por defecto y como máximo absoluto: 900 s (`MAX_RUNTIME_SECONDS`). |

Todo nombre `{campo}` usado en `args` o `label` **debe** existir como
`fields[].id`; si no, el comando se omite.

## Campos de cada entrada (`fields[]`)

| Campo         | Tipo    | Obligatorio | Descripción                                                                  |
|---------------|---------|:-----------:|----------------------------------------------------------------------------|
| `id`          | string  | sí          | Nombre de la variable `{id}` referenciada en `args`.                       |
| `label`       | string  | sí          | Etiqueta del campo en el formulario.                                       |
| `type`        | string  | no          | `text` (por defecto), `number`, `select` o `checkbox`.                     |
| `placeholder` | string  | no          | Texto de ejemplo en el input.                                              |
| `default`     | string/number/bool | no | Valor inicial.                                                      |
| `required`    | bool    | no          | Si es `true`, el campo no puede quedar vacío (ni en el cliente ni en el servidor). |
| `options`     | array[string] | solo para `type: "select"` | Valores permitidos; el servidor rechaza cualquier otro. |
| `validation`  | string  | no          | Nombre de un validador del servidor (ver tabla siguiente).                 |
| `pattern`     | string (regex) | no   | Alternativa a `validation`: el valor debe hacer `fullmatch` contra esta regex. |
| `min` / `max` | number  | no          | Límites para `type: "number"` o para los validadores que los usan.         |

El servidor siempre valida de nuevo en `POST /api/run`, aunque el
formulario ya filtre en el cliente — nunca confíes solo en el JavaScript.

## Validadores disponibles (`validation`)

Definidos en `server.py`, reutilizables desde cualquier JSON sin escribir
código nuevo:

| Nombre            | Qué exige                                                                    |
|-------------------|-------------------------------------------------------------------------------|
| `private_host`    | IP privada, loopback o link-local (IPv4/IPv6). Sin dominios ni IP pública.    |
| `private_url`     | URL `http(s)://` cuyo host cumple `private_host`, sin usuario/contraseña embebidos. |
| `private_cidr`    | Red IPv4 privada (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`); usa `max_addresses` (por defecto 256) para limitar el tamaño. |
| `domain`          | Nombre de dominio válido (no IP, no ruta/URL).                               |
| `ports`           | Lista/rangos de puertos (`80`, `1-1000`, `80,443`); usa `max_ports` para limitar el total. |
| `limited_ports`   | Igual que `ports`, con `max_ports` por defecto 256.                          |
| `scan_rate`, `threads`, `number_range` | Entero dentro de `min`/`max` (por defecto 0–2³¹-1).          |
| `wordlist`        | Ruta que existe como archivo; si se da `options`, debe ser una de esas rutas. |
| `local_file`      | Ruta que existe como archivo local.                                          |
| `pattern`         | Usa el `pattern` del propio campo (equivalente a omitir `validation` y poner solo `pattern`). |

Si un campo no indica `validation` ni `pattern`, solo se aplican las
comprobaciones genéricas (longitud máxima, sin saltos de línea ni bytes
nulos, obligatoriedad, y pertenencia a `options` si es `select`).

La carpeta de scripts opcionales es `~/.local/share/toolfuzz/scripts` en
Linux. Se puede cambiar con la variable de entorno
`TOOLFUZZ_SCRIPTS_DIR`; los entrypoints siguen restringidos a esa carpeta.

## Ejemplo mínimo

Ver `plantilla.json`. Para un ejemplo con varios comandos, selects y
campos numéricos, ver `nmap.json` o `masscan.json`.
