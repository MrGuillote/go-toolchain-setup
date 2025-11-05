#!/usr/bin/env bash
# install-go-advanced.sh
#!/usr/bin/env bash
###############################################################################
# Script Name : install-go-advanced.sh
# Description : Instalador avanzado de Golang (tarball oficial), GoLand (snap/manual)
#               y herramientas Go para entornos Debian/Kali Linux.
# Author      : <Tu nombre o alias>
# Version     : 1.0
# License     : MIT
# Created on  : 2025-11-04
# Last update : 2025-11-04
#
# Usage       : chmod +x install-go-advanced.sh && sudo ./install-go-advanced.sh
#
# Notes       :
#   - Verifica conexión a Internet antes de proceder.
#   - Instala Go desde el tarball oficial con validación SHA256.
#   - Configura GOROOT, GOPATH y PATH automáticamente.
#   - Instala GoLand (vía snap o manualmente desde JetBrains).
#   - Instala herramientas Go populares para pentesting.
#
# Log file    : /var/log/install-go-advanced.log
#
# Tested on   :
#   - Kali Linux 2024.x / 2025.x
#   - Debian 12 (Bookworm)
#
# Example run :
#   sudo ./install-go-advanced.sh
#
# Repository  : https://github.com/<tu-usuario>/<tu-repo>
###############################################################################

set -o errexit
set -o nounset
set -o pipefail

LOGFILE="/var/log/install-go-advanced.log"
exec > >(tee -a "$LOGFILE") 2>&1

# ---------------------------
# Banner
# ---------------------------

# Flag para desactivar reimprimir el banner en traps (por si se quiere silenciar)
KEEP_BANNER_ON_TRAP=true

show_banner() {
  # No usar 'clear' para no borrar otros mensajes; sólo imprimimos el banner.
  cat <<'BANNER'

██████████████████████████████████████████████████████████████████████████████████████
██                                                                                  ██
██              O S I N T  . C O M . A R   |   C I B E R S E G U R I D A D          ██
██                                                                                  ██
██                        G O L A N G   I N S T A L A C I O N                       ██
██                                                                                  ██
██████████████████████████████████████████████████████████████████████████████████████

BANNER
}

# Mostrar banner inmediatamente al iniciar el script
show_banner

: <<'DISABLE_PERIODIC'
BANNER_INTERVAL=15
banner_refresher_pid=""
start_banner_refresher() {
  ( while true; do sleep "$BANNER_INTERVAL"; show_banner; done ) &
  banner_refresher_pid=$!
}
stop_banner_refresher() {
  [ -n "$banner_refresher_pid" ] && kill "$banner_refresher_pid" 2>/dev/null || true
}
# start_banner_refresher
DISABLE_PERIODIC

# Re-imprimir banner si ocurre un error o señal (solo durante la ejecución de este script)
on_err_or_exit() {
  local rc=${1:-$?}
  if [ "${KEEP_BANNER_ON_TRAP:-true}" = true ]; then
    echo "" >&2
    echo "[INFO] Banner reimprimido por trap (codigo: $rc)" >&2
    show_banner >&2
  fi
  # Si se usó refresher en background, lo paramos
  stop_banner_refresher 2>/dev/null || true
  return $rc
}

# Traps: ERR para errores en comandos (con errexit activado), y señales comunes
trap 'on_err_or_exit $?' ERR
trap 'on_err_or_exit 130' INT TERM
trap 'on_err_or_exit 0' EXIT

RETRY_MAX=3
SLEEP_RETRY=5

# Lista de herramientas Go a instalar (puedes editar)
GO_TOOLS=(
  "github.com/tomnomnom/assetfinder"
  "github.com/lc/gau"
  "github.com/tomnomnom/httprobe"
  "github.com/hakluke/hakrawler"
  "github.com/tomnomnom/qsreplace"
  "github.com/hahwul/dalfox"
)

####################
# Helpers
####################
log() { echo "$(date '+%F %T') [INFO]  $*"; }
warn() { echo "$(date '+%F %T') [WARN]  $*"; }
err()  { echo "$(date '+%F %T') [ERROR] $*"; }

error_exit() {
  err "$*"
  err "Revisa el log en $LOGFILE"
  exit 1
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

retry() {
  local n=0
  until [ "$n" -ge "$RETRY_MAX" ]; do
    "$@" && return 0
    n=$((n+1))
    warn "Intento $n/$RETRY_MAX fallido. Reintentando en ${SLEEP_RETRY}s..."
    sleep "$SLEEP_RETRY"
  done
  return 1
}

####################
# Validaciones previas
####################
if [ "$(id -u)" -ne 0 ]; then
  error_exit "Este script necesita ejecutarse con sudo o como root."
fi

log "Detectando distribución..."
if [ -f /etc/os-release ]; then
  . /etc/os-release
  DIST="$ID"
  DIST_LIKE="${ID_LIKE:-}"
  log "Distribución: $PRETTY_NAME ($DIST / $DIST_LIKE)"
else
  warn "No se detectó /etc/os-release; prosiguiendo de todas formas."
fi

log "Comprobando conectividad a internet..."
if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
  warn "No hay conectividad ICMP. Intentaré comprobar resolución DNS..."
  if ! getent hosts go.dev >/dev/null 2>&1; then
    error_exit "Sin conexión de red o DNS. Asegúrate que la máquina puede acceder a internet."
  fi
fi

log "Actualizando repositorios e instalando dependencias básicas..."
apt update -y || warn "apt update falló; continuaré pero puede haber problemas."
apt install -y wget curl tar git ca-certificates unzip python3 >/dev/null || error_exit "Fallo instalando dependencias básicas."

# Aseguramos que python3 exista (para parseo JSON)
if ! command_exists python3; then
  error_exit "python3 es requerido pero no está instalado."
fi

####################
# Función: instalar Go desde tarball oficial
# Usa la API JSON de go.dev para obtener la última versión y checksum
####################
install_go_official() {
  log "Obteniendo información de la última versión de Go desde go.dev..."
  GO_JSON_URL="https://go.dev/dl/?mode=json"
  tmp_json="$(mktemp)"
  if ! retry curl -fsSL "$GO_JSON_URL" -o "$tmp_json"; then
    warn "No pude obtener JSON de go.dev; fallback a apt (si disponible)."
    return 2
  fi

  # Extraer versión, archivo y sha256 usando python
  read -r GO_VERSION GO_FILENAME GO_SHA256 GO_URL <<EOF
$(python3 - <<PY
import json,sys
j=json.load(open("$tmp_json"))
v=j[0]["version"]
for f in j[0]["files"]:
    if f["os"]=="linux" and (f.get("arch")=="amd64" or f.get("arch")=="x86-64"):
        print(v, f["filename"], f.get("sha256",""), "https://go.dev/dl/"+f["filename"])
        sys.exit(0)
print("","", "", "")
PY
)
EOF

  rm -f "$tmp_json"

  if [ -z "$GO_VERSION" ] || [ -z "$GO_FILENAME" ]; then
    warn "No pude parsear la versión desde go.dev. Abortar instalación oficial."
    return 2
  fi

  log "Última versión detectada: $GO_VERSION"
  TMPDIR=$(mktemp -d)
  pushd "$TMPDIR" >/dev/null

  log "Descargando $GO_FILENAME..."
  if ! retry curl -fsSLO "https://go.dev/dl/$GO_FILENAME"; then
    popd >/dev/null
    rm -rf "$TMPDIR"
    error_exit "Descarga del tarball de Go falló."
  fi

  if [ -n "$GO_SHA256" ]; then
    echo "$GO_SHA256  $GO_FILENAME" > go.sha256
    log "Verificando checksum sha256..."
    if ! sha256sum -c go.sha256 >/dev/null 2>&1; then
      popd >/dev/null
      rm -rf "$TMPDIR"
      error_exit "Checksum SHA256 inválido. Descarga corrupta o comprometida."
    fi
  else
    warn "No se obtuvo SHA256 desde la API; omitiendo verificación."
  fi

  # Backup de /usr/local/go si existe
  if [ -d /usr/local/go ]; then
    BACKUP="/usr/local/go.backup.$(date +%s)"
    log "Haciendo backup de /usr/local/go en $BACKUP"
    mv /usr/local/go "$BACKUP" || { popd >/dev/null; rm -rf "$TMPDIR"; error_exit "No se pudo mover /usr/local/go para backup."; }
  fi

  log "Instalando Go en /usr/local ..."
  if ! tar -C /usr/local -xzf "$GO_FILENAME"; then
    warn "La extracción falló. Intentando restaurar backup si existía..."
    [ -n "${BACKUP:-}" ] && mv "$BACKUP" /usr/local/go || true
    popd >/dev/null
    rm -rf "$TMPDIR"
    error_exit "Instalación de Go fallida durante extracción."
  fi

  # Limpiar backup viejo si todo OK
  if [ -n "${BACKUP:-}" ]; then
    log "Eliminando backup antiguo $BACKUP"
    rm -rf "$BACKUP" || warn "No se pudo eliminar backup $BACKUP"
  fi

  popd >/dev/null
  rm -rf "$TMPDIR"
  log "Go $GO_VERSION instalado correctamente en /usr/local/go"
  return 0
}

####################
# Función: configurar entornos en ~/.bashrc (si no están)
####################
configure_env() {
  USER_HOME="${SUDO_USER:+/home/$SUDO_USER}"
  if [ -z "$USER_HOME" ]; then USER_HOME="/root"; fi
  BASHRC="$USER_HOME/.bashrc"

  log "Configurando variables de entorno en $BASHRC..."
  # Añadimos export solo si no existe
  grep -q 'export GOROOT=' "$BASHRC" 2>/dev/null || cat >> "$BASHRC" <<'EOF'

# Go environment (added by install-go-advanced.sh)
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
EOF

  log "Recarga del entorno para el usuario $SUDO_USER (si aplica)."
}

####################
# Función: Instalar Go via apt (fallback)
####################
install_go_apt() {
  log "Instalando golang desde repositorios apt..."
  if apt install -y golang >/dev/null 2>&1; then
    log "Go instalado via apt."
    return 0
  else
    warn "Instalación vía apt falló."
    return 1
  fi
}

####################
# Función: Instalar GoLand
####################
install_goland() {
  # Intentamos snap primero
  if command_exists snap; then
    log "Instalando GoLand vía snap (classic)..."
    if retry snap install goland --classic; then
      log "GoLand instalado vía snap."
      return 0
    else
      warn "snap instalacion falló. Intentaré instalación manual."
    fi
  else
    log "snap no está instalado. Instalando snapd..."
    if apt install -y snapd >/dev/null 2>&1; then
      systemctl enable --now snapd.socket || true
      if retry snap install goland --classic; then
        log "GoLand instalado vía snap."
        return 0
      else
        warn "snap install falló tras instalar snapd."
      fi
    else
      warn "No fue posible instalar snapd."
    fi
  fi

  # Instalación manual (descarga del tar.gz desde jetbrains) - opción simple
  log "Instalación manual de GoLand: descargando paquete de JetBrains (requiere aprobación de licencia manual al abrir)."
  # Nota: descargamos la última release de GoLand desde la página oficial podría requerir seleccionar la versión;
  # aquí proveemos la instrucción para hacerlo manualmente o usar Toolbox.
  warn "La instalación manual requiere que descargues GoLand desde: https://www.jetbrains.com/go/download/ y ejecutes el binario (./goland.sh)."
  return 0
}

####################
# Función: Instalar herramientas Go definidas en GO_TOOLS
####################
install_go_tools() {
  log "Instalando herramientas Go definidas..."
  for tool in "${GO_TOOLS[@]}"; do
    name="$(basename "$tool")"
    log "Instalando $tool ..."
    # Usa 'go install ...@latest' que es la forma recomendada hoy
    # Intentamos con reintentos
    if retry sudo -E GOPATH="/opt/$name" GO111MODULE=on go install "$tool@latest"; then
      BIN_PATH="/opt/$name/bin/$name"
      if [ -f "$BIN_PATH" ]; then
        ln -sf "$BIN_PATH" "/usr/local/bin/$name"
        log "Instalado y enlazado /usr/local/bin/$name"
      else
        warn "Instalado pero no encontré el binario esperado en $BIN_PATH"
      fi
    else
      warn "Fallo instalando $tool. Continuando con las siguientes herramientas."
    fi
  done
}

####################
# MAIN
####################
log "Inicio del instalador avanzado."

# Intentamos instalación oficial primero
if install_go_official; then
  log "Instalación oficial completada."
else
  warn "Instalación oficial no completada; intentando instalación por apt como fallback..."
  if ! install_go_apt; then
    error_exit "No fue posible instalar Go ni vía oficial ni vía apt."
  fi
fi

# Configurar entorno para usuario
configure_env

# Verificar go
if ! command_exists go; then
  warn "El comando 'go' no está en PATH. Intenta ejecutar 'source ~/.bashrc' o reiniciar la sesión."
fi

log "Versión de Go instalada:"
go version || true

# Instalar GoLand (opcional)
install_goland

# Crear /opt con permisos adecuados
mkdir -p /opt
chmod 755 /opt

# Instalar herramientas Go
install_go_tools

log "Instalación completada. Revisa $LOGFILE para detalles."

cat <<EOF
Resumen / próximos pasos:
- Abre una nueva terminal o ejecuta: source ~/.bashrc (para aplicar GOROOT/GOPATH)
- Prueba: go version
- Prueba: go run <archivo>.go
- Si GoLand no se instaló vía snap, descarga desde https://www.jetbrains.com/go/download/
- Si tienes problemas, revisa el log: $LOGFILE
EOF
