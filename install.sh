#!/bin/bash
# Installation and Update script for ssl-cloud

# Ensure we are root
if [ "$EUID" -ne 0 ]; then
  echo "Por favor, ejecuta el script como root (sudo)."
  exit 1
fi

REPO_URL="https://github.com/Depwisescript/ssl-cloud.git"
INSTALL_DIR="/opt/ssl-cloud"

echo "Instalando dependencias (git, golang)..."
apt-get update -y
apt-get install -y git golang-go

if [ -d "$INSTALL_DIR" ]; then
    echo "El directorio ya existe. Actualizando el repositorio..."
    cd $INSTALL_DIR
    git reset --hard HEAD
    git pull origin main
else
    echo "Clonando repositorio..."
    git clone $REPO_URL $INSTALL_DIR
    cd $INSTALL_DIR
fi

# Borrar el certificado viejo para que se regenere siempre que se ejecuta el script de actualización/instalación
echo "Eliminando certificado viejo si existe para forzar su regeneración..."
rm -f /etc/haproxy/yha.pem

echo "Ejecutando la configuración SSL Cloud..."
go run main.go

echo ""
echo "=========================================================="
echo "¡Instalación/Actualización finalizada con éxito!"
echo "HAProxy debería estar escuchando ahora en el puerto 443."
echo "=========================================================="
