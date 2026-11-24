#!/bin/sh
# Double-click launcher in macOS Finder to enable Intel Iris Xe Metal 2 on Golden Gate 27.2.1.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
clear
echo "=============================================================="
echo "  Ativar Aceleracao Grafica Intel Iris Xe (macOS 27.2.1)"
echo "=============================================================="
echo ""
echo "Digite sua senha de administrador do macOS (nao aparece ao digitar) e aperte Enter:"
echo ""
sudo sh "$SCRIPT_DIR/xe-kit/enable-xe-macos27.sh"
RC=$?
echo ""
if [ "$RC" -eq 0 ]; then
    echo "SUCESSO! Agora pode reiniciar o notebook pelo pendrive (OPENCORE -> macOS Golden Gate)."
else
    echo "ERRO (codigo $RC). Tire uma foto desta tela para investigarmos!"
fi
echo ""
printf "Aperte Enter para fechar esta janela..."
read -r _
exit "$RC"
