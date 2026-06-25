# Instalación de secrets-guard en Windows (obligatoria, vía managed-settings)

Esta guía deja el plugin **secrets-guard** instalado, activado y configurado de forma
obligatoria en un equipo Windows, y **deshabilita el modo "bypass permissions"** de Claude
Code. Hay dos caminos: el **automático** (un comando) y el **manual** (paso a paso).

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

> El único requisito por usuario es la CLI de Keeper `ksm` instalada y un perfil
> inicializado (`ksm profile init <token>`). Eso no necesita admin. Ya **no** hay nada que
> instalar a nivel de máquina para el guard; el antiguo servicio `sandbox-dlp` / WinFsp ya
> no se usa.

`SANDBOX` queda en `off` por defecto (solo redacción); `SANDBOX=on` habilita el renderizado
de referencias en sitio. `KERNEL_DLP` está **deprecado / es no-op**. `GUARD_REQUIRED=on`
hace que el guard **falle cerrado** si la bóveda no está disponible; el valor por defecto
`auto` cae al detector de patrones.

## Requisitos previos

- **Claude Code** instalado.
- **Keeper Secrets Manager CLI (`ksm`)** instalada **por cada usuario** y con un perfil
  inicializado (sin admin). Sin esto el plugin se activa, pero cae al detector de patrones
  en vez de al guard de bóveda completa.
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
    "CLAUDE_PLUGIN_OPTION_AUDIT_LOG_PATH": "C:\\ProgramData\\secrets-guard\\audit.log"
  }
}
```

> Las `\\` dobles en la ruta del audit log son obligatorias (escape de JSON).

### 3. (Opcional) Embeber la credencial de Keeper

Si no quieres depender del perfil `ksm` local de cada usuario, agrega dentro de `"env"`:

```json
"KSM_CONFIG": "<base64-keeper-config>"
```

Para obtener el base64: `ksm profile export --file-format json` (o el que ya tengas).
Si lo omites, el guard usa directamente el perfil `ksm` local del usuario.

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

## Qué queda configurado

| Ajuste | Valor | Efecto |
|---|---|---|
| `disableBypassPermissionsMode` | `disable` | No se puede usar el modo bypass de permisos |
| `enabledPlugins` | secrets-guard `true` | Plugin obligatorio, el usuario no puede desactivarlo |
| `strictKnownMarketplaces` | solo hsoft | Solo se puede usar este marketplace |
| `TOOL_INPUT_POLICY` | `deny` | Niega entradas de herramienta con secretos en texto plano |
| `TOOL_OUTPUT_MODE` | `redact` | Redacta secretos en la salida de herramientas |
| `SANDBOX` | `off` | Solo redacción (sin renderizado de referencias). `on` = renderizado en sitio |
| `PRELOAD_SECRETS` | `auto` | Guard proactivo: carga la bóveda local en caché en memoria y bloquea/redacta cualquier valor en prompts y herramientas |
| `GUARD_REQUIRED` | `auto` | `auto` cae al detector si la bóveda no está disponible; `on` falla cerrado; `off` nunca falla cerrado |

> `KERNEL_DLP` está **deprecado / no-op** y ya no se incluye en la configuración.

## Desinstalar / revertir

```powershell
# Quitar la huella por-usuario del guard:
secrets-guard uninstall

# Quitar la política obligatoria machine-wide (necesita admin por ser ruta de máquina):
Remove-Item "C:\ProgramData\ClaudeCode\managed-settings.json" -Force
```
