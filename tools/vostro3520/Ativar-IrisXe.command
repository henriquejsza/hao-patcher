#!/bin/sh
# Double-click launcher in macOS Finder to enable Intel Iris Xe Metal 2 on Golden Gate 27.2.1.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LOG_FILE="$SCRIPT_DIR/ativar-irisxe.log"
clear
echo "=============================================================="
echo "  Ativar Aceleracao Grafica Intel Iris Xe (macOS 27.2.1)"
echo "=============================================================="
echo ""
echo "Log sera salvo em: $LOG_FILE"
echo "Digite sua senha de administrador do macOS (nao aparece ao digitar) e aperte Enter:"
echo ""
sudo -v
RC_FILE=$(mktemp /tmp/xe-rc.XXXXXX)
(
    echo "=== $(date) ==="
    echo "sw_vers: $(sw_vers 2>&1 | tr '\n' ' ')"
    echo "uname: $(uname -a)"
    sudo sh -x "$SCRIPT_DIR/xe-kit/enable-xe-macos27.sh"
    echo $? > "$RC_FILE"
) 2>&1 | tee "$LOG_FILE"
RC=$(cat "$RC_FILE" 2>/dev/null || echo 1)
rm -f "$RC_FILE"
sync
echo ""
if [ "$RC" -eq 0 ]; then
    echo "SUCESSO! Agora pode reiniciar o notebook pelo pendrive (OPENCORE -> macOS Golden Gate)."
else
    echo "ERRO (codigo $RC). Log salvo em $LOG_FILE!"
fi
echo ""
printf "Aperte Enter para fechar esta janela..."
read -r _
exit "$RC"
