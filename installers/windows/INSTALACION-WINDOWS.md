# Instalación de secrets-guard en Windows (obligatoria, vía managed-settings)

Esta guía deja el plugin **secrets-guard** instalado, activado y configurado de forma
obligatoria en un equipo Windows, y **deshabilita el modo "bypass permissions"** de Claude
Code. Hay dos caminos: el **automático** (un comando) y el **manual** (paso a paso).

## Perfiles de instalación

Elige uno:

- **Completa (recomendada) — guard de bóveda total.** Instala el servicio `sandbox-dlp`
  (driver WinFsp). El servicio tiene la credencial y todas las contraseñas de Keeper en
  memoria, así que redacta/bloquea **cualquier** valor de la bóveda (en cualquier
  codificación) antes de que llegue al modelo, aunque no coincida con ningún patrón. Si el
  servicio no está disponible, **falla cerrado** (bloquea por seguridad). Pasos: A o B
  completos (incluido el paso 4, WinFsp).
- **Light — sin WinFsp / sin servicio.** Solo el plugin + `managed-settings.json`; **no**
  ejecutas `sandbox-dlp-setup.ps1` (sin driver de kernel, sin elevación para WinFsp). La
  redacción usa el **detector de patrones** integrado (API keys, tokens, claves AWS,
  llaves privadas…) más los valores resueltos en la sesión. Ver la sección
  [Instalación light](#instalación-light-sin-winfsp--sin-sandbox) abajo. Compromiso: una
  contraseña de Keeper que no coincida con un patrón conocido podría no redactarse — para
  esa garantía usa la completa.

## Requisitos previos

- Windows con permisos de **administrador**.
- **Claude Code** instalado.
- **Keeper Secrets Manager CLI (`ksm`)** instalado y con un perfil canjeado
  (o el `KSM_CONFIG` en base64 a mano). Sin esto el plugin se activa, pero no puede
  resolver secretos.

---

## Opción A — Automática (recomendada)

Abre **PowerShell** y ejecuta (se auto-eleva con UAC y escribe el managed-settings):

```powershell
powershell -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing https://raw.githubusercontent.com/hsoftai/hsoft-claude-plugins/main/installers/windows/enforce-secrets-guard.ps1 -OutFile $env:TEMP\enforce-secrets-guard.ps1; & $env:TEMP\enforce-secrets-guard.ps1"
```

Opcionales (embeber credencial, cambiar proveedor, etc.):

```powershell
& $env:TEMP\enforce-secrets-guard.ps1 -KsmConfig "<base64-keeper-config>" -VaultProvider keeper
```

El script escribe `C:\ProgramData\ClaudeCode\managed-settings.json`. Luego ve al
**paso 4** (servicio kernel-DLP) y al **paso 5** (verificación).

---

## Opción B — Manual (paso a paso)

### 1. Instalar y canjear Keeper `ksm`

Instala la CLI de Keeper Secrets Manager y canjea el token de una sola vez:

```powershell
ksm profile init <ONE-TIME-TOKEN>
ksm secret list        # debe listar tus registros (metadatos)
```

### 2. Crear el archivo managed-settings.json

Crea la carpeta (si no existe) y el archivo, **como administrador**:

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
    "CLAUDE_PLUGIN_OPTION_KERNEL_DLP": "auto",
    "CLAUDE_PLUGIN_OPTION_PRELOAD_SECRETS": "auto",
    "CLAUDE_PLUGIN_OPTION_AUDIT_LOG_PATH": "C:\\ProgramData\\secrets-guard\\audit.log"
  }
}
```

> Las `\\` dobles en la ruta del audit log son obligatorias (escape de JSON).

### 3. (Opcional) Embeber la credencial de Keeper

Si no quieres depender del perfil `ksm` local, agrega dentro de `"env"`:

```json
"KSM_CONFIG": "<base64-keeper-config>"
```

Para obtener el base64: `ksm profile export --file-format json` (o el que ya tengas).
Si lo omites, el servicio `sandbox-dlp` ingiere el perfil `ksm` local en su primer arranque.

### 4. Instalar el servicio kernel-DLP (WinFsp + sandbox-dlp)

Para el renderizado por-proceso de archivos (que el valor solo lo vea el subárbol del
comando y nunca toque disco), instala WinFsp y el servicio. Desde una PowerShell elevada:

```powershell
powershell -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing https://raw.githubusercontent.com/hsoftai/hsoft-claude-plugins/main/installers/windows/sandbox-dlp-setup.ps1 -OutFile $env:TEMP\sandbox-dlp-setup.ps1; & $env:TEMP\sandbox-dlp-setup.ps1"
```

> Sin este paso, `KERNEL_DLP=auto` no tiene servicio al cual delegar; el plugin sigue
> bloqueando/redactando, pero no renderiza archivos por proceso.

### 5. Reiniciar y verificar

Abre una **sesión nueva** de Claude Code (la config se lee al arrancar). Verifica:

```powershell
# El servicio kernel-DLP responde:
secrets-guard dlp-status        # -> running (active=... driver=winfsp)

# El managed-settings quedó bien:
Get-Content "C:\ProgramData\ClaudeCode\managed-settings.json" | ConvertFrom-Json |
  Select-Object -ExpandProperty permissions
```

En Claude Code: el plugin `secrets-guard` aparece habilitado y el modo bypass-permissions
no se puede activar.

---

## Instalación light (sin WinFsp / sin sandbox)

Para equipos donde no quieras instalar el driver WinFsp ni el servicio (sin elevación de
kernel). Solo el plugin + managed-settings; **no** ejecutes `sandbox-dlp-setup.ps1`.

1. Crea `C:\ProgramData\ClaudeCode\managed-settings.json` (admin) con este contenido
   (UTF-8 sin BOM):

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
    "CLAUDE_PLUGIN_OPTION_KERNEL_DLP": "off",
    "CLAUDE_PLUGIN_OPTION_PRELOAD_SECRETS": "off"
  }
}
```

   O con el script: `enforce-secrets-guard.ps1 -KernelDlp off -PreloadSecrets off`.

2. Abre una sesión nueva de Claude Code. (No hay servicio que verificar.)

**Qué protege la instalación light:** bloquea/redacta secretos que coincidan con el
detector de patrones (API keys, tokens, claves AWS, llaves privadas, etc.), valores
resueltos en la sesión, y bloquea prompts/herramientas con esos secretos.

**Qué NO cubre (vs. completa):** el matching contra **todas** las contraseñas de Keeper —
ese guard necesita el servicio (único poseedor de la credencial en Windows). Una
contraseña de Keeper que no matchee un patrón conocido podría no redactarse. Para la
garantía total ("ninguna contraseña de la bóveda llega al modelo"), usa la instalación
**completa**.

## Qué queda configurado

| Ajuste | Valor | Efecto |
|---|---|---|
| `disableBypassPermissionsMode` | `disable` | No se puede usar el modo bypass de permisos |
| `enabledPlugins` | secrets-guard `true` | Plugin obligatorio, el usuario no puede desactivarlo |
| `strictKnownMarketplaces` | solo hsoft | Solo se puede usar este marketplace |
| `TOOL_INPUT_POLICY` | `deny` | Niega entradas de herramienta con secretos en texto plano |
| `TOOL_OUTPUT_MODE` | `redact` | Redacta secretos en la salida de herramientas |
| `SANDBOX` / `KERNEL_DLP` | `auto` | Renderiza referencias por-proceso (valor nunca a disco) |
| `PRELOAD_SECRETS` | `auto` | Guard proactivo: bloquea/redacta cualquier valor de la bóveda en prompts, herramientas y lecturas de archivo |

## Desinstalar / revertir

```powershell
Remove-Item "C:\ProgramData\ClaudeCode\managed-settings.json" -Force
```

(Esto solo quita la política obligatoria; el servicio `sandbox-dlp` se desinstala con su
propio desinstalador de WinFsp y quitando la tarea/entrada de autostart.)
