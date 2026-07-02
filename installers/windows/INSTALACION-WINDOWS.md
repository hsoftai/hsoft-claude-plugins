# Instalación de secrets-guard en Windows (obligatoria, vía managed-settings)

Esta guía deja el plugin **secrets-guard** instalado, activado y configurado de forma
obligatoria en un equipo Windows, y **deshabilita el modo "bypass permissions"** de Claude
Code. Hay dos caminos: el **automático** (un comando) y el **manual** (paso a paso).

**Resumen por usuario** (una vez desplegado el managed-settings, todo SIN admin):

```powershell
secrets-guard install   # instala el CLI de Keeper si falta, PIDE tu one-time token,
                        # inicializa el perfil y VALIDA la conexión — todo interactivo
secrets-guard doctor    # verifica el estado local
```

`secrets-guard install` ahora hace el onboarding completo: detecta/instala el CLI de Keeper
(winget), te pide el **one-time token** de forma interactiva, ejecuta `ksm profile init` por
ti y valida que la bóveda responde. Con `require_vault=on` (por defecto), mientras no haya
bóveda configurada Claude Code **bloquea los prompts** y muestra estos pasos.

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

El managed-settings de abajo viene en **modo estricto** (Keeper obligatorio, bloqueo por
defecto): `REQUIRE_VAULT=on` bloquea los prompts con onboarding si no hay bóveda;
`GUARD_REQUIRED=on` hace que el guard **falle cerrado** (bloquea prompts/entradas/salidas que
no se puedan verificar contra la bóveda, en vez de degradar al detector); `PRELOAD_SECRETS=on`
carga toda la bóveda y redacta/bloquea cualquier valor. Si prefieres no bloquear, cambia
`REQUIRE_VAULT`/`GUARD_REQUIRED` a `off`/`auto` (degrada al detector y nunca brickea).

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
    "CLAUDE_PLUGIN_OPTION_PRELOAD_SECRETS": "on",
    "CLAUDE_PLUGIN_OPTION_GUARD_REQUIRED": "on",
    "CLAUDE_PLUGIN_OPTION_REQUIRE_VAULT": "on",
    "CLAUDE_PLUGIN_OPTION_AUDIT_LOG_PATH": "C:\\ProgramData\\secrets-guard\\audit.log"
  }
}
```

> **Este es el ÚNICO `managed-settings.json` que se usa.** Pégalo tal cual. Está en **modo
> estricto: Keeper obligatorio y bloqueo por defecto** —
> - `REQUIRE_VAULT=on`: si NO hay bóveda configurada, bloquea los prompts y muestra cómo
>   configurarla (`secrets-guard install` instala el CLI de Keeper, pide el token, hace
>   `ksm profile init` y valida).
> - `GUARD_REQUIRED=on`: falla cerrado — si el guard no puede verificar un prompt/entrada/
>   salida contra la bóveda, **bloquea** en vez de degradar.
> - `PRELOAD_SECRETS=on`: carga TODA la bóveda en caché y redacta/bloquea cualquier valor en
>   prompts, entradas, salidas y lecturas de archivos.
>
> Para una postura **no bloqueante** (degradar al detector cuando falte la bóveda), cambia
> `REQUIRE_VAULT` y `GUARD_REQUIRED` a `auto`/`off`.

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

### 3. Cómo se provee la credencial de la bóveda (dos estrategias)

El bloque de arriba **no** incluye credencial: por defecto cada usuario configura su perfil
con `secrets-guard install` (paso 4). Elige UNA estrategia:

- **Per-usuario (recomendada, por defecto):** no agregues nada al managed-settings. Cada
  usuario ejecuta `secrets-guard install`, que instala el CLI de Keeper, pide su one-time
  token, hace `ksm profile init` y valida. secrets-guard autodetecta el perfil (incl.
  `~/.keeper/keeper.ini`) desde cualquier directorio.
- **Credencial de flota (opcional):** si prefieres una sola credencial machine-wide para
  todos (sin perfil local por usuario), **añade una única clave dentro de `env`** del bloque
  de arriba: `"KSM_CONFIG": "<base64>"` (obtén el base64 con `ksm profile export
  --file-format json`). Si la usas, rellénala de verdad — **no dejes un placeholder**, porque
  un `KSM_CONFIG` inválido rompe la resolución y desactiva la autodetección del perfil local.

> ⚠️ **No pongas `KSM_INI_FILE` en el managed-settings.** Los valores de `env` se aplican
> **literales**: Claude Code **no** expande `%USERPROFILE%` ni `${HOME}`, así que una ruta
> per-usuario no resolvería. Usa la autodetección (por defecto) o, si el `keeper.ini` está en
> una ruta no estándar, que el usuario fije `KSM_INI_FILE` a nivel de Usuario en su shell.

### 4. Instalar la CLI y verificar

El plugin instala su propio CLI al iniciar la sesión (hook SessionStart, sin admin). Para el
onboarding completo de la bóveda, ejecuta:

```powershell
secrets-guard install          # instala el CLI de Keeper si falta, PIDE tu one-time token,
                               # hace `ksm profile init` y VALIDA la conexión (interactivo)
secrets-guard doctor           # reporta el estado local de bóveda/guard

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
| `PRELOAD_SECRETS` | `on` | Guard proactivo: carga TODA la bóveda en caché en memoria y redacta/bloquea cualquier valor en prompts y salidas de herramientas (incl. lecturas de archivos). `on` y `auto` son equivalentes; **`off` lo desactiva** (solo se redactan valores resueltos en la sesión, y un `Read` de un secreto no referenciado queda **sin censurar**) |
| `GUARD_REQUIRED` | `on` | **Falla cerrado** (modo estricto): bloquea prompts/entradas/salidas que no se puedan verificar contra la bóveda. `auto` degrada al detector si la bóveda no está disponible (no brickea); `off` nunca falla cerrado |
| `REQUIRE_VAULT` | `on` | Onboarding obligatorio: si NO hay bóveda configurada, bloquea los prompts y muestra los pasos (carpeta compartida → app en Secrets Manager → token → `secrets-guard install`). `off` permite usar sin bóveda (degrada al detector) |
| `KSM_CONFIG` | base64 (o ausente) | Credencial de Keeper machine-wide para toda la flota; si se omite, cada usuario usa su perfil `ksm`/`keeper-ksm` local |

> `KSM_INI_FILE` **no** se pone en el managed-settings (los valores son literales, sin
> expansión de `%USERPROFILE%`); secrets-guard autodetecta `~/.keeper/keeper.ini` por usuario.

## Desinstalar / revertir

```powershell
# Quitar la huella por-usuario del guard:
secrets-guard uninstall

# Quitar la política obligatoria machine-wide (necesita admin por ser ruta de máquina):
Remove-Item "C:\ProgramData\ClaudeCode\managed-settings.json" -Force
```
