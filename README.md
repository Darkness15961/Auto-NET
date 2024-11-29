# Auto Net

**Auto Net** es una herramienta diseñada para automatizar la configuración de redes en sistemas Linux. Facilita la gestión de interfaces de red, el enrutamiento NAT, y la configuración de servidores DHCP a través de un menú interactivo, permitiendo a los administradores de sistemas y usuarios configurar redes con facilidad.

## Descripción

El objetivo de **Auto Net** es simplificar y automatizar los procesos técnicos de configuración de redes en entornos Linux. Con esta herramienta, los usuarios pueden:

- Detectar interfaces de red disponibles.
- Configurar reglas de NAT y enrutamiento con `iptables`.
- Configurar un servidor DHCP para asignar direcciones IP dinámicas.
- Realizar configuraciones permanentes mediante `netplan`.

## Características

- **Detección automática de interfaces de red**: El programa identifica y muestra las interfaces de red disponibles en el sistema.
- **Configuración de NAT y enrutamiento**: Utiliza `iptables` para definir reglas de NAT y habilitar el reenvío de paquetes entre redes.
- **Servidor DHCP**: Configura y gestiona un servidor DHCP que asigna direcciones IP dinámicas a los dispositivos en la red.
- **Persistencia de configuraciones**: Las configuraciones de red se aplican de forma permanente utilizando `netplan`.

## Requisitos

Para ejecutar **Auto Net**, se necesitan los siguientes paquetes en el sistema Linux:

- `isc-dhcp-server`
- `iptables`
- `dnsmasq`
- `iproute2`
- `net-tools`

## Instalación

### Clonar el repositorio

Para clonar el repositorio en tu máquina local, usa el siguiente comando:

```bash
https://github.com/Darkness15961/Auto-NET.git
