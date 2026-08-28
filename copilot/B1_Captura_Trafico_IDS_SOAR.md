# B1 --- Generación y captura de tráfico

## Objetivo

Generar tráfico benigno y los cuatro escenarios de ataque del
laboratorio y almacenarlos en PCAP.

## Tráfico benigno

Se trabajó con tráfico normal del laboratorio, incluyendo:

-   navegación web hacia la víctima;
-   sesiones SSH;
-   transferencias y comunicación normal.

Los PCAP permiten repetir las mismas pruebas y sirven como evidencia
para validar el pipeline y el modelo.

## Escenarios de ataque

### 1. Escaneo SYN rápido

``` bash
nmap -sS -T4 192.168.56.10
```

Produce muchos intentos de conexión en poco tiempo.

### 2. Escaneo lento

``` bash
nmap -T1 192.168.56.10
```

Representa un patrón low-and-slow, útil para comprobar que el sistema no
dependa únicamente de umbrales simples.

### 3. SYN flood controlado

Se utilizó `hping3` con tasa limitada. La tasa debe mantenerse
controlada porque una inundación sin límite puede saturar la captura y
provocar pérdida de paquetes.

### 4. Fuerza bruta SSH

Se utilizó `hydra` contra el servicio SSH de la víctima para generar
intentos repetidos de autenticación.

## Organización

``` text
pcaps/
├── benigno/
└── ataques/
    ├── nmap_rapido.pcap
    ├── nmap_lento.pcap
    ├── syn_flood.pcap
    └── hydra_ssh.pcap
```

## Relación con el componente de IA

B1 desbloquea la validación del modelo porque entrega tráfico real del
laboratorio. El flujo es:

``` text
Laboratorio
   ↓
Captura
   ↓
PCAP
   ↓
Validación / calibración del modelo
```

## Seguridad

Todos los ataques se realizan exclusivamente contra:

``` text
192.168.56.10
```

dentro de la red aislada.

## Criterio de terminado

B1 queda listo cuando existen PCAP de tráfico benigno y de los cuatro
ataques y pueden ser procesados por el componente correspondiente.
