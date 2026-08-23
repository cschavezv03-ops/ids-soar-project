# B2 --- Flow y FlowManager

## Objetivo

Convertir paquetes individuales en flujos de red y producir el vector de
24 características que utilizará el modelo.

``` text
Paquetes → 5-tupla → Flow → 24 features → Modelo
```

## 1. Clase Flow

Un `Flow` representa una conversación identificada por:

``` text
IP origen
IP destino
Puerto origen
Puerto destino
Protocolo
```

Es la 5-tupla.

Se implementó almacenamiento de:

-   cantidad de paquetes;
-   bytes totales;
-   timestamps;
-   timestamps Forward/Backward;
-   tamaños de paquetes Forward/Backward;
-   TCP flags.

## 2. Forward y Backward

El primer sentido observado es Forward y el contrario es Backward.

``` text
Forward:  A → B
Backward: B → A
```

Esto permite calcular estadísticas separadas para cada dirección.

## 3. IAT

Se implementó el Inter-Arrival Time:

``` text
timestamps = [10.0, 10.5, 12.0]
IAT        = [0.5, 1.5]
```

También se calculan:

-   IAT medio;
-   IAT desviación estándar;
-   IAT Forward;
-   IAT Backward;
-   medias por dirección.

## 4. Tasa de paquetes

Se implementó la tasa de paquetes por segundo:

``` text
paquetes / duración
```

Ejemplo:

``` text
3 paquetes / 2 s = 1.5 paquetes/s
```

## 5. Tamaños de paquetes

Se implementaron estadísticas para ambas direcciones.

### Forward

-   media;
-   desviación estándar;
-   máximo.

### Backward

-   media;
-   desviación estándar;
-   máximo.

Durante las pruebas se detectó y corrigió un error en el cálculo de
varianza. La expresión correcta utiliza:

``` python
(x - mean) ** 2
```

y no:

``` python
x - mean ** 2
```

La corrección evitó obtener una desviación estándar compleja.

## 6. TCP Flags

Se implementó el conteo de:

``` text
SYN
ACK
FIN
RST
PSH
```

Estas características representan el comportamiento de establecimiento,
transferencia y cierre de conexiones TCP.

## 7. Byte ratio

Se incorporó la relación de bytes entre Forward y Backward para
representar la asimetría del flujo.

## 8. Vector de 24 features

Se implementó:

``` python
get_features()
```

y se verificó:

``` python
len(flow.get_features()) == 24
```

Esto cumple el contrato de integración: el modelo recibe un vector fijo
de 24 valores numéricos.

## 9. FlowManager

Se creó `FlowManager` para administrar los flows activos:

``` python
self.flows = {}
```

La clave utiliza la 5-tupla.

### Reutilización

Se comprueba:

1.  clave normal;
2.  clave inversa.

Así, estos paquetes pertenecen al mismo Flow:

``` text
A → B
B → A
A → B
```

## 10. process_packet()

`process_packet()`:

1.  obtiene o crea el Flow;
2.  añade el paquete;
3.  comprueba FIN/RST;
4.  devuelve el Flow si debe cerrarse.

## 11. Cierre por FIN

``` python
if tcp_flags and ("F" in tcp_flags or "R" in tcp_flags):
```

FIN provoca el cierre normal del flujo.

## 12. Cierre por RST

RST provoca el cierre abrupto del flujo.

Ambos eliminan el flow de los activos y devuelven el objeto para
procesar sus características.

## 13. Timeout de inactividad --- 15 s

Para inactividad se utiliza el último paquete:

``` python
last_packet_time = flow.timestamps[-1]
```

Si:

``` text
current_time - last_packet_time >= 15
```

el Flow expira.

## 14. Timeout activo --- 120 s

Para la duración total se utiliza el primer paquete:

``` python
first_packet_time = flow.timestamps[0]
```

Si:

``` text
current_time - first_packet_time >= 120
```

el Flow expira.

### Bug encontrado

Inicialmente se utilizó por error:

``` python
flow.timestamps[-1]
```

para el timeout activo. Eso calculaba desde el último paquete.

La corrección fue:

``` python
flow.timestamps[0]
```

### Prueba final

Con:

``` text
timestamps = [10.0, 50.0, 100.0]
current_time = 130.0
```

se obtuvo:

``` text
Duration: 120.0
Expired: True
Paquetes: 3
Bytes: 500
Features: 24
```

## 15. Estado actual de B2

### Completado

-   [x] Flow.
-   [x] 5-tupla.
-   [x] Forward/Backward.
-   [x] paquetes y bytes.
-   [x] timestamps.
-   [x] IAT.
-   [x] estadísticas IAT.
-   [x] tasas.
-   [x] tamaños Forward.
-   [x] tamaños Backward.
-   [x] estadísticas de tamaños.
-   [x] TCP flags.
-   [x] byte ratio.
-   [x] vector de 24 features.
-   [x] FlowManager.
-   [x] reutilización bidireccional.
-   [x] FIN.
-   [x] RST.
-   [x] timeout de inactividad de 15 s.
-   [x] timeout activo de 120 s.

### Pendiente

La siguiente integración es:

``` text
Scapy / PCAP
      ↓
paquetes reales
      ↓
FlowManager
      ↓
Flow
      ↓
24 features
      ↓
modelo
```

También queda implementar la evaluación por ventanas parciales para
poder detectar ataques antes de que un Flow termine.

## Arquitectura alcanzada

``` text
          PAQUETE
             ↓
       FlowManager
             ↓
          5-tupla
             ↓
           Flow
        ↙       ↘
   Forward     Backward
        ↘       ↙
       24 features
             ↓
           Modelo
```

B2 deja lista la capa de ensamblado de flujos para conectarla con Scapy,
inferencia y posteriormente SOAR.
