# Instalación de secrets-guard en Windows (obligatoria, vía managed-settings)

Esta guía deja el plugin **secrets-guard** instalado, activado y configurado de forma
obligatoria en un equipo Windows, y **deshabilita el modo "bypass permissions"** de Claude
Code. Hay dos caminos: el **automático** (un comando) y el **manual** (paso a paso).

**Resumen por usuario** (una vez desplegado el managed-settings, todo SIN admin):

```powershell
ksm profile init <ONE-TIME-TOKEN>   # 1. inicializa tu bóveda Keeper
secrets-guard install               # 2. instala/configura el guard (o se auto-instala al abrir Claude Code)
secrets-guard doctor                # 3. verifica el estado local
```

Si `secrets-guard` aún no está en el PATH (equipo recién provisionado, antes del primer
arranque de Claude Code), ábrelo una vez —el plugin instala el CLI solo— o invócalo por ruta
completa: `& "$env:LOCALAPPDATA\secrets-guard\bin\secrets-guard.exe" install`.

## Cómo funciona (modelo local — sin WinFsp, sin servicio, sin admin)

Desde la v0.6.0, secrets-guard se ejecuta **enteramente por usuario: sin servicio del
sistema, sin driver WinFsp y sin permisos de administrador**. El guard de redacción lee la
bóveda del propio usuario a través de su perfil local `ksm` / `op` (en su ubicación por
defecto — no se mueve ni se borra), carga todos los valores en una caché en memoria por
sesión al iniciar, y redacta/bloquea **cualquiera** de esos valores (en cualquier
codificación) en los prompts y en la entrada/salida de herramientas antes de que lleguen al
modelo. Si el perfil de la bóveda no está inicializado, el guard cae al **detector de
patrones** integrado (API keys, tokens, claves AWS, llaves privadas…) y nunca bloquea el
uso normal.

> El único requisito por usuario es la CLI de Keeper (`ksm` **o** el binario standalone
> `keeper-ksm`) instalada y un perfil inicializado (`ksm profile init <token>`). Eso no
> necesita admin. Ya **no** hay nada que instalar a nivel de máquina para el guard; el
> antiguo servicio `sandbox-dlp` / WinFsp ya no se usa.

> **Desde 0.7.1**, secrets-guard detecta el CLI de Keeper bajo cualquiera de sus dos nombres
> (`ksm` del paquete pip o `keeper-ksm.exe` del release standalone) y encuentra el perfil
> aunque el `keeper.ini` esté en una carpeta per-usuario (`~/.keeper/keeper.ini` o `~/`):
> exporta `KSM_INI_FILE` solo e inyecta `--ini-file`, así el perfil carga sin importar el
> directorio de trabajo. Ya **no** hace falta fijar `KSM_INI_FILE` a mano en la mayoría de
> los equipos.

`SANDBOX` queda en `off` por defecto (solo redacción); `SANDBOX=on` habilita el renderizado
de referencias en sitio. `KERNEL_DLP` está **deprecado / es no-op**. El valor por defecto
`GUARD_REQUIRED=auto` cae al detector de patrones cuando la bóveda no está disponible (nunca
brickea el uso). `GUARD_REQUIRED=on` hace que el guard **falle cerrado**: además de bloquear
prompts/entradas sin verificar, **bloquea la salida de una herramienta cuando hay una bóveda
configurada pero sus valores no se pudieron cargar** (no se puede garantizar que la salida no
contenga un secreto, así que se retiene "si no se puede redactar, se bloquea la lectura").

## Requisitos previos

- **Claude Code** instalado.
- **Keeper Secrets Manager CLI** instalada **por cada usuario** y con un perfil inicializado
  (sin admin). Vale cualquiera de sus dos nombres: `ksm` (paquete pip) o `keeper-ksm.exe`
  (release standalone); secrets-guard detecta ambos. Sin esto el plugin se activa, pero cae
  al detector de patrones en vez de al guard de bóveda completa. (Alternativa para flota:
  embeber `KSM_CONFIG` en el managed-settings, ver paso 3.)
- Permisos de **administrador** **solo** para escribir el `managed-settings.json` machine-
  wide (la política obligatoria). El guard en sí **no** necesita admin.

---

## Opción A — Automática (recomendada)

Abre **PowerShell** y ejecuta (se auto-eleva con UAC solo para escribir el managed-settings):

```powershell
powershell -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing https://raw.githubusercontent.com/hsoftai/hsoft-claude-plugins/main/installers/windows/enforce-secrets-guard.ps1 -OutFile $env:TEMP\enforce-secrets-guard.ps1; & $env:TEMP\enforce-secrets-guard.ps1"
```

Opcionales (embeber credencial, cambiar proveedor, etc.):

```powershell
& $env:TEMP\enforce-secrets-guard.ps1 -KsmConfig "<base64-keeper-config>" -VaultProvider keeper
```

El script escribe `C:\ProgramData\ClaudeCode\managed-settings.json`. Luego, **cada usuario**
prepara su bóveda (paso 1 de la Opción B) y va al **paso 4** (verificación).

---

## Opción B — Manual (paso a paso)

### 1. Instalar e inicializar Keeper `ksm` (por usuario, sin admin)

Instala la CLI de Keeper Secrets Manager e inicializa el perfil con el token de una sola vez:

```powershell
winget install KeeperSecurity.KeeperSecretsManager
ksm profile init <ONE-TIME-TOKEN>
ksm secret list        # debe listar tus registros (metadatos)
```

El guard lee este perfil local directamente; no se mueve, no se borra y no requiere admin.

### 2. Crear el archivo managed-settings.json

Crea la carpeta (si no existe) y el archivo, **como administrador** (solo porque
`ProgramData` es una ruta de máquina; no es por secrets-guard):

```powershell
New-Item -ItemType Directory -Force -Path "C:\ProgramData\ClaudeCode" | Out-Null
notepad "C:\ProgramData\ClaudeCode\managed-settings.json"
```

Pega este contenido y **guárdalo como UTF-8 (sin BOM)**:

```json
{
  "permissions": {
    "disableBypassPermissionsMode": "disable",
    "defaultMode": "default"
  },
  "extraKnownMarketplaces": {
    "hsoft-claude-plugins": {
      "source": { "source": "github", "repo": "hsoftai/hsoft-claude-plugins" },
      "autoUpdate": true
    }
  },
  "strictKnownMarketplaces": [
    { "source": "github", "repo": "hsoftai/hsoft-claude-plugins" }
  ],
  "enabledPlugins": {
    "secrets-guard@hsoft-claude-plugins": true
  },
  "env": {
    "CLAUDE_PLUGIN_OPTION_VAULT_PROVIDER": "keeper",
    "CLAUDE_PLUGIN_OPTION_BLOCK_ON_PROMPT_SECRET": "true",
    "CLAUDE_PLUGIN_OPTION_TOOL_INPUT_POLICY": "deny",
    "CLAUDE_PLUGIN_OPTION_TOOL_OUTPUT_MODE": "redact",
    "CLAUDE_PLUGIN_OPTION_SANDBOX": "off",
    "CLAUDE_PLUGIN_OPTION_PRELOAD_SECRETS": "auto",
    "CLAUDE_PLUGIN_OPTION_GUARD_REQUIRED": "auto",
    "CLAUDE_PLUGIN_OPTION_AUDIT_LOG_PATH": "C:\\ProgramData\\secrets-guard\\audit.log",
    "KSM_CONFIG": "<base64-keeper-config>"
  }
}
```

> Las `\\` dobles en cualquier ruta (audit log, `KSM_INI_FILE`) son obligatorias (escape de JSON).

> 🚨 **`PRELOAD_SECRETS` debe ser `auto` (o `on`) para censurar lecturas de archivos.** Este
> es el ajuste que decide si secrets-guard carga **toda** la bóveda en caché y compara cada
> valor contra prompts y **salidas de herramientas**. Si lo pones en **`off`**, el guard solo
> redacta valores que se resolvieron **durante esa sesión**: un `Read` de un archivo (o
> cualquier salida) que contenga un secreto de la bóveda **NO se censura ni se bloquea**,
> aunque `list_secrets` funcione. Si ves que el modelo lista los secretos pero muestra un
> valor sin censurar al leer un archivo, **revisa que `CLAUDE_PLUGIN_OPTION_PRELOAD_SECRETS`
> no esté en `off`**. Verifícalo con `secrets-guard doctor` (avisa si la precarga está
> apagada).

#### Credencial de la bóveda — elige UNA estrategia

`KSM_CONFIG` es la forma **recomendada para flota**: una sola credencial base64 machine-wide
que funciona para **todos** los usuarios sin depender de un perfil `ksm` local ni de la
ubicación del `keeper.ini`. Obtenla con `ksm profile export --file-format json` y pégala como
valor de `KSM_CONFIG`. Si la usas, `KSM_INI_FILE` se ignora (tiene precedencia y no necesita
INI).

> 🚨 **Rellena o elimina `KSM_CONFIG` — no dejes el placeholder.** Si guardas el JSON con el
> literal `<base64-keeper-config>` sin reemplazar, la bóveda **deja de funcionar**: ksm
> intentará usar esa config inválida y, además, secrets-guard omite la autodetección del
> `keeper.ini` local cuando `KSM_CONFIG` está presente. Si **no** vas a embeber credencial,
> **borra la línea `KSM_CONFIG` por completo** y cada usuario usa su perfil `ksm`/`keeper-ksm`
> local (autodetectado, ver más abajo).

> ⚠️ **`KSM_INI_FILE` y la NO-expansión de variables.** Los valores de `env` del
> managed-settings se aplican **literales**: Claude Code **no** expande `%USERPROFILE%` ni
> `${HOME}`. Por eso **no** pongas `"KSM_INI_FILE": "%USERPROFILE%\\.keeper\\keeper.ini"` en el
> archivo machine-wide (quedaría literal y no resolvería). Opciones correctas:
> - **No lo pongas** (recomendado): 0.7.1 autodetecta `~/.keeper/keeper.ini` por usuario.
> - **Embebe `KSM_CONFIG`** (arriba): no depende de ningún `keeper.ini`.
> - **Per-usuario** (solo si el `keeper.ini` está en una ruta no estándar): que el propio
>   usuario lo fije con
>   `[Environment]::SetEnvironmentVariable("KSM_INI_FILE", "$env:USERPROFILE\.keeper\keeper.ini", "User")`
>   y reinicie Claude Code. Ahí sí se expande, porque lo resuelve el shell al arrancar.

### 3. (Opcional) Embeber la credencial de Keeper

El bloque de arriba ya incluye la línea `KSM_CONFIG`. Rellénala con el base64 de tu perfil
para que la bóveda funcione machine-wide sin perfil `ksm` local por usuario:

```json
"KSM_CONFIG": "<base64-keeper-config>"
```

Para obtener el base64: `ksm profile export --file-format json` (o el que ya tengas).
Si prefieres que cada usuario use su propio perfil `ksm` local, **elimina la línea
`KSM_CONFIG`** del managed-settings.

### 4. Instalar la CLI y verificar

El plugin instala su CLI automáticamente al iniciar la sesión (hook SessionStart, sin
admin). También puedes instalarla a mano y verificar el estado local:

```powershell
secrets-guard install          # instala la CLI en el PATH del usuario (sin admin),
                               # limpia componentes legacy, revisa la bóveda y calienta la caché
secrets-guard doctor           # reporta el estado local de bóveda/guard
secrets-guard dlp-status       # estado del guard local

# El managed-settings quedó bien:
Get-Content "C:\ProgramData\ClaudeCode\managed-settings.json" | ConvertFrom-Json |
  Select-Object -ExpandProperty permissions
```

Abre una **sesión nueva** de Claude Code (la config se lee al arrancar). El plugin
`secrets-guard` aparece habilitado y el modo bypass-permissions no se puede activar.

### 5. Desinstalar (por usuario)

```powershell
secrets-guard uninstall        # quita toda la huella por-usuario de secrets-guard (sin admin)
```

Para quitar la política obligatoria machine-wide, ver "Desinstalar / revertir" abajo.

## (Opcional) Telemetría / observabilidad (OpenTelemetry)

Si tu organización envía métricas y logs de Claude Code a un colector OpenTelemetry, agrega
estas claves **dentro del mismo bloque `"env"`** del managed-settings (reemplaza el endpoint
y el token por los tuyos):

```json
"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
"OTEL_LOGS_EXPORTER": "otlp",
"OTEL_METRICS_EXPORTER": "otlp",
"OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
"OTEL_EXPORTER_OTLP_ENDPOINT": "https://<tu-endpoint-otel>/otlp",
"OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Bearer <tu-token>",
"OTEL_LOG_USER_PROMPTS": "1",
"OTEL_LOG_TOOL_DETAILS": "1",
"OTEL_LOG_RAW_API_BODIES": "1",
"OTEL_RESOURCE_ATTRIBUTES": "client.surface=code,company=<tu-empresa>",
"OTEL_METRIC_EXPORT_INTERVAL": "10000",
"OTEL_LOGS_EXPORT_INTERVAL": "2000"
```

> ⚠️ **Seguridad — léelo antes de activar el logging de contenido.** secrets-guard protege
> el **contexto del modelo** (lo que llega a Claude), **no** un canal de telemetría aparte.
> `OTEL_LOG_USER_PROMPTS`, `OTEL_LOG_TOOL_DETAILS` y sobre todo `OTEL_LOG_RAW_API_BODIES`
> exportan prompts, detalles de herramientas y **cuerpos crudos de la API** a tu colector, y
> pueden capturar exactamente los secretos que secrets-guard evita filtrar al modelo.
> Actívalos solo si el colector aplica su propia redacción o confías plenamente en ese
> destino; si no, déjalos en `"0"` o quítalos. El token va en texto plano en el
> managed-settings (legible por admin) — trátalo como credencial y no uses un placeholder
> en producción.

## Qué queda configurado

| Ajuste | Valor | Efecto |
|---|---|---|
| `disableBypassPermissionsMode` | `disable` | No se puede usar el modo bypass de permisos |
| `enabledPlugins` | secrets-guard `true` | Plugin obligatorio, el usuario no puede desactivarlo |
| `strictKnownMarketplaces` | solo hsoft | Solo se puede usar este marketplace |
| `TOOL_INPUT_POLICY` | `deny` | Niega entradas de herramienta con secretos en texto plano |
| `TOOL_OUTPUT_MODE` | `redact` | Redacta secretos en la salida de herramientas |
| `SANDBOX` | `off` | Solo redacción (sin renderizado de referencias). `on` = renderizado en sitio |
| `PRELOAD_SECRETS` | `auto` | Guard proactivo: carga la bóveda local en caché en memoria y redacta/bloquea cualquier valor en prompts y salidas de herramientas (incl. lecturas de archivos). **`off` lo desactiva**: solo se redactan valores resueltos en la sesión, y un `Read` de un secreto no referenciado queda **sin censurar** |
| `GUARD_REQUIRED` | `auto` | `auto` cae al detector si la bóveda no está disponible (no brickea). `on` falla cerrado: bloquea prompts/entradas sin verificar **y** la salida de una herramienta si la bóveda está configurada pero no cargó. `off` nunca falla cerrado |
| `KSM_CONFIG` | base64 (o ausente) | Credencial de Keeper machine-wide para toda la flota; si se omite, cada usuario usa su perfil `ksm`/`keeper-ksm` local |

> `KERNEL_DLP` está **deprecado / no-op** y ya no se incluye en la configuración.
> `KSM_INI_FILE` **no** se pone en el managed-settings (los valores son literales, sin
> expansión de `%USERPROFILE%`); 0.7.1 autodetecta `~/.keeper/keeper.ini` por usuario.

## Desinstalar / revertir

```powershell
# Quitar la huella por-usuario del guard:
secrets-guard uninstall

# Quitar la política obligatoria machine-wide (necesita admin por ser ruta de máquina):
Remove-Item "C:\ProgramData\ClaudeCode\managed-settings.json" -Force
```
