# SSL Cloud (HAProxy Tunnel Test)

Este repositorio contiene la configuración para instalar y probar HAProxy con soporte SSL (puerto 443) y redirección interna a un servicio SSH-WS (puerto 10015). Incluye la generación de un certificado simulando el comportamiento de Cloudflare para las pruebas con HTTP Injector.

## Instalación (Un solo comando)
Para instalar y ejecutar por primera vez en tu VPS, corre el siguiente comando como root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Depwisescript/ssl-cloud/main/install.sh)
```

## Actualización (Un solo comando)
Si hay una nueva versión del código en el repositorio y deseas actualizar tu VPS y aplicarla automáticamente, el comando es exactamente el mismo:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Depwisescript/ssl-cloud/main/install.sh)
```

### ¿Qué hace este comando?
- Instala las dependencias necesarias (`git` y `golang-go`).
- Clona este repositorio en `/opt/ssl-cloud` (o lo actualiza usando `git pull` si ya existe).
- Borra el certificado SSL de prueba viejo y lo regenera automáticamente con los parámetros de Cloudflare.
- Ejecuta el script de Go que instala y reinicia HAProxy en el puerto 443 con la configuración multiplataforma y su backend local.
