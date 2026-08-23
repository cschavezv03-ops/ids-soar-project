# B0 --- Montaje del laboratorio IDS + SOAR

## Objetivo

Preparar un laboratorio aislado y controlado para desarrollar y probar
el IDS + SOAR sin afectar sistemas reales.

### Topología

``` text
VM-ATACANTE                         VM-VICTIMA
192.168.56.20                      192.168.56.10
Kali Linux                         Fedora 44
nmap / hping3 / hydra              IDS + SOAR
       \                              /
        +------ 192.168.56.0/24 ------+
                 vboxnet0
```

## Trabajo realizado

-   Se definió la víctima `192.168.56.10` y la atacante `192.168.56.20`.
-   Se utilizó una red host-only `192.168.56.0/24`.
-   La víctima aloja los servicios objetivo, principalmente SSH y web.
-   La atacante genera tráfico benigno y los escenarios de ataque.
-   Se preparó el entorno para trabajar de forma aislada.
-   Se consideró un snapshot de la víctima antes de modificar el
    firewall.
-   Durante las pruebas, `firewalld` puede detenerse para evitar
    interferencias con las reglas de contención.

## ¿Por qué B0 es importante?

El proyecto necesita reproducibilidad y seguridad. La red aislada
permite generar tráfico de prueba sin atacar sistemas externos y permite
recuperar la VM mediante snapshot si una regla del IDS bloquea
accidentalmente la conectividad.

## Criterio de terminado

B0 queda listo cuando las VMs se comunican entre sí por la red de
laboratorio y no dependen de Internet para las pruebas.

## Resultado

``` text
Laboratorio aislado
        ↓
Generación de tráfico
        ↓
Captura
        ↓
Pipeline IDS + SOAR
```
