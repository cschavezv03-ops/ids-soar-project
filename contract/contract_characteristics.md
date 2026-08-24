# Contrato de características — 24 features

**Proyecto:** Sistema de Detección de Intrusiones de Red con Respuesta Automática SOAR
**Componente:** A — Inteligencia y datos
**Versión:** 1.0 · agosto 2026
**Estado:** congelado. Pendiente de validación de paridad.

---

## 1. Qué es este documento

Este es el único punto de contacto entre los dos componentes del sistema. Define
**exactamente** qué 24 números describen un flujo de red, en qué orden, con qué
unidad y con qué tratamiento de valores ausentes.

El modelo no observa tráfico: observa un vector de 24 números. Ese vector debe
significar lo mismo durante el entrenamiento (sobre el dataset CICIDS2017) y durante
la inferencia en vivo (sobre tráfico capturado en el laboratorio). Si ambos caminos
difieren, el modelo recibe en producción algo distinto de lo que aprendió y falla
**sin emitir ningún error**.

Cualquier cambio en el número de características o en su orden rompe el componente B
y exige subir la versión de este documento y notificarlo explícitamente.

---

## 2. La interfaz de código

```python
# src/intelligence/extractor.py — provisto por el componente A
def extract_features(flow) -> list[float]:
    """Recibe un flujo ensamblado y devuelve exactamente 24 valores,
    siempre en el orden de la sección 4."""

# src/intelligence/model.py — provisto por el componente A
def predict(feature_vector: list[float]) -> float:
    """Recibe el vector de 24 características y devuelve la probabilidad
    de que el flujo sea un ataque, entre 0.0 y 1.0."""
```

Toda la normalización de unidades descrita en la sección 5 ocurre **dentro** de
`extract_features`. El componente B recibe valores ya normalizados y no necesita
conocer ninguna de las conversiones.

---

## 3. Cómo se seleccionaron: de 78 candidatas a 24

El dataset CICIDS2017 aporta 78 columnas de características. La reducción se hizo en
dos etapas: primero se **eliminó** lo inutilizable por criterios objetivos, después se
**midió** cuántas de las restantes hacen falta.

### 3.1 Eliminación por criterios objetivos

| Paso | Criterio | Se quitan | Quedan |
|---|---|---|---|
| 0 | Columnas del CSV, excluida `Label` | — | 78 |
| 1 | **Identidad** — `Destination Port` produce fuga de datos | 1 | 77 |
| 2 | **Duplicado del archivo** — `Fwd Header Length.1` repite otra columna | 1 | 76 |
| 3 | **Varianza cero** — 8 columnas constantes en 0 | 8 | 68 |
| 4 | **Duplicados exactos** — 5 columnas idénticas o derivadas de otra | 5 | 63 |
| 5 | **Irreproducibles en vivo** — las columnas de banderas TCP (§6.1) | 10 | 53 |
| 6 | **Huella de entorno** — ventana TCP inicial (§6.2) | 2 | **51** |

Ninguno de estos pasos es una preferencia: cada uno responde a una propiedad
verificable del dataset, reproducible con `src/intelligence/audit_dataset.py`.

### 3.2 Medición del número necesario

Las 51 características utilizables se ordenaron por importancia — calculada
**únicamente sobre el conjunto de entrenamiento**, sin acceso al de prueba — y se
midió el rendimiento de un Random Forest en función de cuántas se usan:

| Nº de características | F1 (clase ataque) | PR-AUC | Ganancia marginal |
|---|---|---|---|
| 5 | 0,9387 | 0,9653 | — |
| 10 | 0,9451 | 0,9690 | +0,0064 |
| 20 | 0,9629 | 0,9895 | +0,0178 |
| **24** | **0,9685** | **0,9938** | **+0,0056** |
| 30 | 0,9685 | 0,9939 | +0,0000 |
| 51 (todas) | 0,9689 | 0,9944 | +0,0004 |

**El rendimiento satura en 24 características.** Emplear las 51 disponibles mejora el
F1 en cuatro diezmilésimas.

### 3.3 Justificación del número

1. **Rendimiento saturado.** Medido en 3.2: más allá de 24, la ganancia es nula.
2. **Coste de validación de paridad.** La condición de salida de la fase 0 exige
   verificar, característica por característica, que cada valor coincide entre el CSV
   y el extractor en vivo. Ese trabajo crece linealmente con el número de
   características, y una característica no validada es peor que su ausencia.
3. **Superficie de riesgo.** Cada característica adicional es una oportunidad más de
   introducir una dependencia del entorno de entrenamiento, como la documentada en 6.2.
4. **Latencia de inferencia.** El sistema evalúa flujos completos y ventanas parciales
   de forma continua; el criterio de aceptación incluye la latencia de contención p95.
5. **Estabilidad de la interfaz.** 24 es el tamaño acordado entre ambos componentes
   desde el inicio del proyecto. Modificarlo sin ganancia medible contradice el
   propósito mismo de un contrato.

---

## 4. Las 24 características

Orden congelado. La posición forma parte del contrato tanto como el nombre.

Los nombres del CSV se muestran ya normalizados con `df.columns.str.strip()`; en el
archivo original varios llevan un espacio inicial inconsistente.

### Grupo 1 — Duración y volumen (posiciones 0–4)

*Distinguen un escaneo (flujos minúsculos) de una inundación (gran número de paquetes).*

| # | Nombre | Columna CSV | Columna extractor | Tipo | Unidad |
|---|---|---|---|---|---|
| 0 | `flow_duration` | `Flow Duration` | `flow_duration` | float | µs |
| 1 | `tot_fwd_pkts` | `Total Fwd Packets` | `tot_fwd_pkts` | int | paquetes |
| 2 | `tot_bwd_pkts` | `Total Backward Packets` | `tot_bwd_pkts` | int | paquetes |
| 3 | `totlen_fwd_pkts` | `Total Length of Fwd Packets` | `totlen_fwd_pkts` | float | bytes de payload |
| 4 | `totlen_bwd_pkts` | `Total Length of Bwd Packets` | `totlen_bwd_pkts` | float | bytes de payload |

### Grupo 2 — Tamaños de paquete, sentido de ida (posiciones 5–8)

*La fuerza bruta produce tamaños muy regulares; el tráfico legítimo, variados.*

| # | Nombre | Columna CSV | Columna extractor | Tipo | Unidad |
|---|---|---|---|---|---|
| 5 | `fwd_pkt_len_min` | `Fwd Packet Length Min` | `fwd_pkt_len_min` | float | bytes de payload |
| 6 | `fwd_pkt_len_mean` | `Fwd Packet Length Mean` | `fwd_pkt_len_mean` | float | bytes de payload |
| 7 | `fwd_pkt_len_std` | `Fwd Packet Length Std` | `fwd_pkt_len_std` | float | bytes de payload |
| 8 | `fwd_pkt_len_max` | `Fwd Packet Length Max` | `fwd_pkt_len_max` | float | bytes de payload |

### Grupo 3 — Tamaños de paquete, sentido de vuelta (posiciones 9–12)

*La respuesta del servidor revela si la conversación es real o solo sondeo.*

| # | Nombre | Columna CSV | Columna extractor | Tipo | Unidad |
|---|---|---|---|---|---|
| 9 | `bwd_pkt_len_min` | `Bwd Packet Length Min` | `bwd_pkt_len_min` | float | bytes de payload |
| 10 | `bwd_pkt_len_mean` | `Bwd Packet Length Mean` | `bwd_pkt_len_mean` | float | bytes de payload |
| 11 | `bwd_pkt_len_std` | `Bwd Packet Length Std` | `bwd_pkt_len_std` | float | bytes de payload |
| 12 | `bwd_pkt_len_max` | `Bwd Packet Length Max` | `bwd_pkt_len_max` | float | bytes de payload |

### Grupo 4 — Tamaños del flujo completo (posiciones 13–14)

*Resumen global de la conversación, en ambos sentidos.*

| # | Nombre | Columna CSV | Columna extractor | Tipo | Unidad |
|---|---|---|---|---|---|
| 13 | `pkt_len_mean` | `Packet Length Mean` | `pkt_len_mean` | float | bytes de payload |
| 14 | `pkt_len_std` | `Packet Length Std` | `pkt_len_std` | float | bytes de payload |

### Grupo 5 — Ritmo temporal (posiciones 15–20)

*Donde se delata el escaneo lento: espaciado artificial entre paquetes.*

| # | Nombre | Columna CSV | Columna extractor | Tipo | Unidad |
|---|---|---|---|---|---|
| 15 | `flow_iat_mean` | `Flow IAT Mean` | `flow_iat_mean` | float | µs |
| 16 | `flow_iat_std` | `Flow IAT Std` | `flow_iat_std` | float | µs |
| 17 | `flow_iat_max` | `Flow IAT Max` | `flow_iat_max` | float | µs |
| 18 | `flow_iat_min` | `Flow IAT Min` | `flow_iat_min` | float | µs |
| 19 | `fwd_iat_mean` | `Fwd IAT Mean` | `fwd_iat_mean` | float | µs |
| 20 | `bwd_iat_mean` | `Bwd IAT Mean` | `bwd_iat_mean` | float | µs |

### Grupo 6 — Tasas y datos útiles (posiciones 21–23)

*Velocidad de la conversación y si transporta contenido real.*

| # | Nombre | Columna CSV | Columna extractor | Tipo | Unidad |
|---|---|---|---|---|---|
| 21 | `flow_pkts_s` | `Flow Packets/s` | `flow_pkts_s` | float | paquetes/s |
| 22 | `flow_byts_s` | `Flow Bytes/s` | `flow_byts_s` | float | bytes/s |
| 23 | `fwd_act_data_pkts` | `act_data_pkt_fwd` | `fwd_act_data_pkts` | int | paquetes |

### Lista para el código

```python
# src/intelligence/contract.py
CONTRACT_VERSION = "1.0"

FEATURES_24 = [
    "flow_duration",        #  0
    "tot_fwd_pkts",         #  1
    "tot_bwd_pkts",         #  2
    "totlen_fwd_pkts",      #  3
    "totlen_bwd_pkts",      #  4
    "fwd_pkt_len_min",      #  5
    "fwd_pkt_len_mean",     #  6
    "fwd_pkt_len_std",      #  7
    "fwd_pkt_len_max",      #  8
    "bwd_pkt_len_min",      #  9
    "bwd_pkt_len_mean",     # 10
    "bwd_pkt_len_std",      # 11
    "bwd_pkt_len_max",      # 12
    "pkt_len_mean",         # 13
    "pkt_len_std",          # 14
    "flow_iat_mean",        # 15
    "flow_iat_std",         # 16
    "flow_iat_max",         # 17
    "flow_iat_min",         # 18
    "fwd_iat_mean",         # 19
    "bwd_iat_mean",         # 20
    "flow_pkts_s",          # 21
    "flow_byts_s",          # 22
    "fwd_act_data_pkts",    # 23
]

CSV_COLUMNS_24 = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Fwd Packet Length Max",
    "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Bwd Packet Length Max",
    "Packet Length Mean", "Packet Length Std",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Mean", "Bwd IAT Mean",
    "Flow Packets/s", "Flow Bytes/s", "act_data_pkt_fwd",
]

assert len(FEATURES_24) == len(CSV_COLUMNS_24) == 24
```

---

## 5. Reglas de normalización

El dataset CICIDS2017 fue generado con CICFlowMeter (implementación Java, 2017). El
extractor en vivo emplea `cicflowmeter` (implementación Python). Son
reimplementaciones distintas y dos familias de características se miden de forma
diferente.

**Dirección de la conversión: el extractor se adapta al CSV, nunca al revés.** El
extractor dispone de información más rica que el CSV descartó, y la transformación
inversa es imposible, no simplemente incómoda: no existe operación que reconstruya
las cabeceras y el relleno de trama a partir del payload.

### R1 — Tiempo en microsegundos

| | CSV | Extractor sin normalizar |
|---|---|---|
| Unidad | microsegundos | segundos |
| Evidencia | máximo 1,2×10⁸ con timeout activo de 120 s | flujo de 60 ms → `0.06` |

**Aplica a:** posiciones 0, 15, 16, 17, 18, 19, 20.
**Regla:** el extractor emite todos los valores temporales en microsegundos.

### R2 — Tamaño de paquete medido como payload, relleno de Ethernet incluido

| | CSV | Extractor sin normalizar |
|---|---|---|
| Definición | bytes de payload, **contando el relleno de Ethernet** | longitud de trama completa |
| Evidencia | `Fwd Packet Length Max` mediana **0** en 33.150 flujos de PortScan | SYN sin datos → `54` (14 Ethernet + 20 IP + 20 TCP) |

**Aplica a:** posiciones 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 22.
**Regla:** el extractor calcula la longitud de paquete como longitud del payload de
transporte, no de la trama, **incluyendo el relleno** que la capa de enlace añade
para alcanzar la trama mínima de 60 bytes.

El matiz del relleno no es cosmético. Ethernet exige 60 bytes por trama y un paquete
TCP sin opciones mide 54, de modo que viaja rellenado con 6 bytes de ceros. El
CICFlowMeter de Java que generó el dataset **cuenta ese relleno como payload**, y el
extractor debe replicarlo. Evidencia: en 158.870 flujos de PortScan, el RST con que
un puerto cerrado responde —un paquete que no transporta ningún dato— informa de
`Bwd Packet Length Min` = **6** en el 99,26 % de los casos, y de 0 en el 0,44 %
restante, que son los puertos abiertos, cuyo SYN-ACK lleva opciones TCP y cuya trama
supera los 60 bytes sin necesidad de relleno. Como las cabeceras TCP crecen en
palabras de 4 bytes, los únicos valores de relleno posibles son 6, 2 y 0.

**Esta precisión no modifica el contrato ni su versión.** No cambian el número de
características, ni su orden, ni sus unidades, ni la lista de posiciones a las que R2
se aplica: cambia únicamente el detalle de cómo se implementa la medición, que antes
quedaba subespecificado. El contrato permanece en la versión 1.0.

> La normalización se implementa modificando la **medición**, no restando una
> constante a posteriori. La conversión es por tanto exacta. El detalle del relleno
> es además la razón por la que restar una constante sería insuficiente: la
> diferencia entre trama y payload depende de las opciones TCP de cada paquete.
> El desarrollo completo está en `copilot/cicflowmeter_bugs.md`, sección 6.

### R3 — Valores no finitos

`Flow Bytes/s` y `Flow Packets/s` producen infinito o NaN cuando la duración del flujo
es cero. En el dataset completo: 1.358 NaN y 1.509 infinitos en la primera; 2.867
infinitos en la segunda.

**Regla:** `+inf`, `-inf` y `NaN` se sustituyen por `0.0`, de forma idéntica en el
preprocesamiento del dataset y en el extractor en vivo.

### R4 — Filas corruptas

22 flujos presentan `Flow Duration` negativa. Se eliminan durante el preprocesamiento
del dataset (Tarea A3). No requieren tratamiento en vivo.

---

## 6. Características excluidas y su justificación

### 6.1 Las cinco columnas de banderas TCP

Excluidas: `FIN Flag Count`, `SYN Flag Count`, `RST Flag Count`, `PSH Flag Count`,
`ACK Flag Count`, junto con `URG Flag Count`, `CWE Flag Count`, `ECE Flag Count`,
`Fwd PSH Flags` y `Fwd URG Flags`.

Estas columnas figuraban en la propuesta inicial del contrato por su valor conocido en
detección: un escaneo de puertos se caracteriza por SYN y RST sin ACK. La auditoría del
dataset completo mostró que **no contienen la información que su nombre indica**.

**Evidencia 1 — conversaciones TCP sin acuses de recibo.** Sobre los 101.677 flujos
con al menos 4 paquetes en cada sentido y más de 1 ms de duración:

| Columna | Vale 0 en |
|---|---|
| `ACK Flag Count` | **80,8 %** |
| `SYN Flag Count` | 98,1 % |
| `FIN Flag Count` | 95,7 % |

Un intercambio de ocho paquetes sin un solo ACK es incompatible con el funcionamiento
del protocolo TCP.

**Evidencia 2 — combinaciones imposibles.** De las 32 combinaciones posibles de cinco
indicadores binarios, en 2.830.743 flujos aparecen únicamente 10, y en ningún caso hay
más de dos banderas activas simultáneamente. Una conexión HTTP completa presenta SYN,
ACK, PSH y FIN.

**Evidencia 3 — columnas idénticas byte a byte.** Comparación de todas las columnas
sobre el dataset completo:

```
['Fwd PSH Flags', 'SYN Flag Count']   → idénticas en 2.830.743 filas
['Fwd URG Flags', 'CWE Flag Count']   → idénticas en 2.830.743 filas
```

`Fwd PSH Flags` mide la bandera PSH en sentido de ida; `SYN Flag Count` mide la
bandera SYN. Son magnitudes distintas y contienen exactamente los mismos valores.

**Evidencia 4 — escaneo SYN sin banderas SYN.** En 33.150 flujos etiquetados como
`PortScan` no existe ninguno con `SYN Flag Count = 1` ni con `RST Flag Count = 1`. Un
escaneo SYN contra un puerto cerrado consiste, por definición, en SYN → RST.

**Criterio de exclusión.** Las columnas no están dañadas: son consistentes y
reproducibles. El problema es que no corresponden a la magnitud que declaran, y se
desconoce a cuál corresponden. Reproducirlas en el extractor exigiría replicar
deliberadamente el defecto de una herramienta de terceros, lo que no es verificable.

**Coste medido de la exclusión:** el F1 desciende de 0,9635 a 0,9598, es decir 0,0037.

**Consecuencia si no se excluyeran:** el extractor en vivo calcula las banderas
correctamente. Ante un escaneo real reportaría un número elevado de SYN, mientras que
el modelo habría aprendido del CSV que un escaneo se caracteriza por SYN = 0. El
sistema fallaría precisamente en el escenario de ataque más simple.

### 6.2 Ventana TCP inicial

Excluidas: `Init_Win_bytes_forward`, `Init_Win_bytes_backward`.

Al entrenar con el conjunto completo de características utilizables, estas dos
resultaron ser las de mayor importancia y elevaron el F1 hasta 0,9948. Su distribución
explica el motivo:

| Etiqueta | `Init_Win_bytes_forward` (mediana) | Valores distintos |
|---|---|---|
| BENIGN | 119 | 5.776 |
| PortScan | 29200 | 6 |
| SSH-Patator | 29200 | 4 |
| DoS slowloris | 29200 | 3 |
| Web Attack (3 variantes) | 29200 | 5 |

29200 es el tamaño de ventana TCP inicial por defecto de Linux. CICIDS2017 se generó
empleando una única máquina atacante con sistema Linux frente a víctimas con otros
sistemas operativos. La característica identifica **el sistema operativo del equipo
atacante**, no el comportamiento del ataque.

**Motivo de la exclusión.** El entorno de despliegue de este proyecto emplea dos
máquinas virtuales con el mismo sistema operativo (Fedora 44). En ese entorno la
característica (a) no discrimina, porque atacante y víctima presentan valores
idénticos, y (b) induciría falsos positivos sistemáticos, al haber aprendido el modelo
que los valores propios de Linux corresponden a tráfico de ataque.

Es un caso concreto de **desfase de dominio**, identificado como riesgo principal del
proyecto.

**Principio general derivado:** se excluye toda característica que identifique el
entorno en lugar del comportamiento, con independencia de su rendimiento offline.

### 6.3 Identidad — fuga de datos

Excluidas: dirección IP de origen y destino, puertos de origen y destino, marca de
tiempo e identificador de flujo. En el CSV empleado, `Destination Port`.

Incluirlas permitiría al modelo memorizar la identidad del atacante en lugar de
aprender la forma del ataque: produciría métricas casi perfectas en evaluación y un
fallo completo ante un cambio de dirección o de puerto.

### 6.4 Varianza cero

Excluidas por ser constantes en 0 en las 2.830.743 filas: `Bwd PSH Flags`,
`Bwd URG Flags`, `Fwd Avg Bytes/Bulk`, `Fwd Avg Packets/Bulk`, `Fwd Avg Bulk Rate`,
`Bwd Avg Bytes/Bulk`, `Bwd Avg Packets/Bulk`, `Bwd Avg Bulk Rate`.

### 6.5 Duplicados exactos

Excluidas por ser idénticas o derivadas exactas de otra columna ya presente:

| Columna excluida | Equivale a |
|---|---|
| `Subflow Fwd Packets` | `Total Fwd Packets` |
| `Subflow Bwd Packets` | `Total Backward Packets` |
| `Subflow Fwd Bytes` | `Total Length of Fwd Packets` |
| `Avg Fwd Segment Size` | `Fwd Packet Length Mean` |
| `Avg Bwd Segment Size` | `Bwd Packet Length Mean` |
| `Fwd Header Length.1` | `Fwd Header Length` |

### 6.6 Nota sobre `Down/Up Ratio`

La propuesta inicial del contrato incluía esta característica como medida de simetría.
Se excluyó por dos motivos: resultó la de menor importancia entre las candidatas
(0,0039) y requería una tercera regla de normalización, al emplear el CSV división
entera (valores 0 a 32) frente al valor en coma flotante del extractor.

La información de simetría se conserva de forma implícita: al disponer el modelo de
volúmenes de ida y de vuelta por separado (posiciones 1–4), puede construir la
relación que necesite.

---

## 7. Rendimiento de referencia

Random Forest sin ajuste de hiperparámetros, 480.000 flujos muestreados de los 8
archivos, partición estratificada 70/30.

| Métrica | Valor | Criterio del proyecto |
|---|---|---|
| F1, clase ataque | **0,960** | ≥ 0,90 ✅ |
| Precisión | 0,938 | — |
| Recall | 0,983 | — |
| PR-AUC | 0,993 | — |

Detección por familia de ataque:

| Familia | Recall |
|---|---|
| PortScan | 0,999 |
| DDoS | 0,998 |
| DoS slowloris | 0,993 |
| FTP-Patator | 0,993 |
| DoS Hulk | 0,975 |
| DoS GoldenEye | 0,946 |
| DoS Slowhttptest | 0,938 |
| SSH-Patator | 0,500 |

**Sobre SSH-Patator.** La menor tasa de detección se debe a que, en CICIDS2017, esta
familia se separa principalmente mediante la ventana TCP inicial, excluida por el
motivo expuesto en 6.2. Se aborda por tres vías: la deduplicación del playbook agrupa
las alertas de un mismo origen en un único caso, de modo que detectar la mitad de los
flujos de un ataque de fuerza bruta sigue produciendo la contención; el umbral de
decisión se fija en la Tarea A6 considerando explícitamente este caso; y la Tarea A7
recalibra el modelo con capturas del propio laboratorio.

Estas cifras corresponden a la selección de características, no a la evaluación final
del modelo, que se realiza en la Tarea A5 sobre una partición independiente.

---

## 8. Reproducibilidad

Todas las afirmaciones cuantitativas de este documento se reproducen con:

```bash
python src/intelligence/audit_dataset.py
```

El script opera en modo solo lectura sobre `data/raw/` y no modifica los CSV
originales. Normaliza únicamente los nombres de columna (`str.strip()`), nunca los
valores.

---

## 9. Control de versiones del contrato

| Versión | Fecha | Cambio |
|---|---|---|
| 1.0 | agosto 2026 | Versión inicial. 24 características, 2 reglas de normalización. |

La Tarea A2 valida la paridad entre el CSV y el extractor en vivo, característica por
característica, sobre capturas del laboratorio. Si alguna no alcanza la paridad, se
retira del contrato, se sustituye y este documento pasa a la versión 1.1, notificando
el cambio al componente B.

## 10. Mapeo de etiquetas

CICIDS2017 contiene 15 valores de etiqueta. El modelo se entrena sobre BENIGN y
ocho familias de ataque; el resto se descarta antes del entrenamiento.

Excluir no equivale a marcar como benigno: las filas se eliminan, de modo que el
modelo nunca forma opinión sobre ellas. Marcarlas como benignas le enseñaría que
ese tráfico es normal, y marcarlas como ataque añadiría ejemplos de escenarios
ajenos a la demostración.

| Etiqueta | Flujos | Destino |
|---|---|---|
| BENIGN | 2.273.097 | 0 |
| DoS Hulk | 231.073 | 1 |
| PortScan | 158.930 | 1 |
| DDoS | 128.027 | 1 |
| DoS GoldenEye | 10.293 | 1 |
| FTP-Patator | 7.938 | 1 |
| SSH-Patator | 5.897 | 1 |
| DoS slowloris | 5.796 | 1 |
| DoS Slowhttptest | 5.499 | 1 |
| Bot | 1.966 | excluida — no es escenario de la demostración |
| Web Attack (3 variantes) | 2.180 | excluida — no es escenario de la demostración |
| Infiltration | 36 | excluida — volumen insuficiente para estratificar |
| Heartbleed | 11 | excluida — volumen insuficiente para estratificar |

**Resultado:** 2.826.550 flujos conservados, de los cuales 553.453 son ataques
(19,58 %). Se descarta el 0,15 % del dataset. El desbalance resultante es de 4,1
a 1, lo que justifica emplear F1 y PR-AUC en lugar de exactitud —un clasificador
que respondiera siempre «normal» alcanzaría un 80,4 %— sin requerir remuestreo.

**Nota de implementación.** Las etiquetas `Web Attack` contienen la secuencia de
bytes `EF BF BD` (U+FFFD) grabada en el archivo original. La cadena resultante en
Python depende de la codificación empleada al leer, por lo que estas etiquetas se
identifican por prefijo ASCII y nunca por comparación literal. El mapeo es
`intelligence.contract.label_to_target()`, que lanza una excepción ante cualquier
etiqueta no listada: un valor por defecto contaminaría el conjunto de
entrenamiento en silencio.