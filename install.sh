#!/usr/bin/env bash
# Agent Security Evaluation — setup per il team di sicurezza aziendale
# Prerequisiti: Python 3 con pip

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

if [ -n "$CONDA_PREFIX" ] && [ -x "$CONDA_PREFIX/bin/python3" ]; then
  PYTHON="$CONDA_PREFIX/bin/python3"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON="python"
else
  echo "Error: Python 3 is required. Install it and re-run install.sh."
  exit 1
fi

PYTHON_VERSION=$("$PYTHON" -c 'import sys; sys.stdout.write("{}.{}".format(sys.version_info[0], sys.version_info[1]))')
PYTHON=$("$PYTHON" -c 'import sys; sys.stdout.write(sys.executable)')
PYTHON_MAJOR=${PYTHON_VERSION%%.*}
PYTHON_MINOR=${PYTHON_VERSION#*.}

if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 11 ]; }; then
  echo "ERROR: ASE requires Python 3.11 or later. Found Python $PYTHON_VERSION."
  echo "   Please install or activate a Python 3.11+ environment and re-run install.sh."
  exit 1
fi

if [ -n "$CONDA_PREFIX" ]; then
  PIP="$CONDA_PREFIX/bin/pip"
elif command -v pip3 >/dev/null 2>&1; then
  PIP="pip3"
elif command -v pip >/dev/null 2>&1; then
  PIP="pip"
else
  echo "Error: pip is required. Install it and re-run install.sh."
  exit 1
fi

if ! "$PIP" install -r "$SCRIPT_DIR/dashboard_v2/requirements.txt"; then
  exit 1
fi

BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"

LAUNCHER="$BIN_DIR/ase-dashboard"
DASHBOARD_DIR="$SCRIPT_DIR/dashboard_v2"

cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
DASHBOARD_DIR="\${ASE_DASHBOARD_DIR:-$DASHBOARD_DIR}"
PORT="\${ASE_DASHBOARD_PORT:-8080}"
export ASE_DASHBOARD_PORT="\$PORT"
cd "\$DASHBOARD_DIR"
exec $PYTHON -m backend.main "\$@"
EOF
chmod +x "$LAUNCHER"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    SHELL_PROFILE=""
    if [ -n "$ZSH_VERSION" ] || [ "$(basename "$SHELL")" = "zsh" ]; then
      SHELL_PROFILE="$HOME/.zshrc"
    else
      SHELL_PROFILE="$HOME/.bashrc"
    fi
    echo "export PATH=\"$HOME/.local/bin:\$PATH\"" >> "$SHELL_PROFILE"
    echo "Aggiunto ~/.local/bin a $SHELL_PROFILE. Esegui: source $SHELL_PROFILE"
    ;;
esac

cat <<EOF

ASE installato.

Avvio dashboard:
  ase-dashboard              — http://localhost:8080/overview

Configurazione (variabili d'ambiente):
  ASF_ROOT        — percorso alla directory agent-security-framework
                    (contiene il file asf_local.db da monitorare)
  ASF_AUDIT_DB    — percorso diretto al file asf_local.db o asf_test.db (override di ASF_ROOT)
  ASE_DASHBOARD_PORT — porta HTTP (default 8080)

Esempio per il team di sicurezza:
  ASF_ROOT=/path/to/agent-security-framework ase-dashboard
EOF
