# Nota A7 — Recalibración contra el tráfico del laboratorio

**Tarea:** A7, recalibrar con tráfico propio.
**Contrato:** v1.0, sin cambios. **El modelo no se reentrena.**
**Decisión:** `config.py` pasa de **0,70 / 0,90** a **0,50 / 0,70**.
**Evidencia:** `scripts/scripts_output/recalibration_report.txt` (segunda pasada),
`scripts/scripts_output/lab_calibration_report.txt` (primera), y
`reports/figures/recalibration_lab.png`.

> **Resumen: el umbral se pudo ajustar y el escaneo se recupera. La inundación
> no, y no es cuestión de umbral.**
>
> - **Escaneo de puertos:** de **0,6 % a 57 %** de detección por flujo. Resuelto.
> - **SYN flood:** **0 % a cualquier umbral usable.** No es desfase de dominio ni
>   calibración: CICIDS2017 **no contiene ni un solo flujo** con la firma de
>   nuestra inundación, así que el modelo extrapola en una región que nunca
>   aprendió.
> - **Fuerza bruta SSH:** marginal. Necesitaría un umbral ≤ 0,25, donde el 7,4 %
>   del tráfico benigno se marcaría como ataque. Inviable.

---

## 0. Las dos pasadas

| | Primera pasada | Segunda pasada |
|---|---|---|
| Capturas | `data/pcap/pcap_v1.0/` | `data/pcap/pcap_v2.0/` |
| Flujos benignos | **2** | **12.029** |
| Offload de la tarjeta | activo (tramas de 7.240 B) | **desactivado** (máx. 1514 B) |
| Módulo | `lab_calibration.py` | `recalibrate.py` |
| Resultado | diagnóstico, sin poder decidir | **decisión tomada** |

La primera pasada encontró el problema y no pudo arreglarlo: con 2 flujos
benignos el intervalo de confianza sobre la tasa de falsos positivos iba de
0,02 % a 67 %. Frank entregó el segundo juego con el offload desactivado y
12.029 flujos benignos, y con eso sí se puede elegir un corte.

---

## 1. El nuevo punto de operación

| | Antes (A6) | **Ahora (A7)** |
|---|---|---|
| `THRESHOLD` / `SEV_MEDIUM` | 0,70 | **0,50** |
| `SEV_HIGH` | 0,90 | **0,70** |

### Qué gana, en el laboratorio

| Captura | a 0,70 | **a 0,50** |
|---|---|---|
| `nmap` lento | 2,2 % | **66,3 %** |
| `nmap` rápido | 0,4 % | **56,4 %** |
| Falsos positivos benignos | 58 de 12.029 | **188 de 12.029** (1,56 %) |

Por cada falso positivo se detectan **3,8 flujos de escaneo**. Y con la
agrupación del SOAR, la probabilidad de perder un escaneo entero es
prácticamente cero (10⁻⁴⁴ para el escaneo lento de 92 flujos).

### Qué cuesta, en CICIDS2017 — casi nada

El recall **sube en las nueve familias** y la precisión baja 0,0019:

| Familia | a 0,70 | a 0,50 | |
|---|---|---|---|
| DoS Hulk | 0,9924 | 0,9942 | +0,0018 |
| DDoS | 0,9987 | 0,9990 | +0,0003 |
| DoS GoldenEye | 0,9781 | 0,9859 | +0,0078 |
| FTP-Patator | 0,9949 | 0,9983 | +0,0034 |
| DoS slowloris | 0,9926 | 0,9926 | 0,0000 |
| DoS Slowhttptest | 0,9856 | 0,9952 | +0,0096 |
| SSH-Patator | 0,9587 | 0,9667 | +0,0080 |
| **PortScan** | 0,8779 | **0,9429** | **+0,0650** |
| Falsos positivos | 626 | 757 | +131 |

**El umbral de A6 estaba de más, incluso para CICIDS2017.** Se eligió con la
lógica correcta —coste asimétrico— pero sobre una tasa base que no era la
nuestra.

### Por qué `SEV_HIGH` baja a 0,70

**Ningún flujo de ataque del laboratorio supera 0,72.** Con la banda alta en
0,90 nunca se activaría en nuestra red, y una respuesta graduada que nunca
gradúa no es un diseño, es decoración.

---

## 2. La inundación: por qué ningún umbral la arregla

Las tres capturas de `hping3` a 10, 100 y 1000 paquetes/s producen **107.981
flujos y UN SOLO vector de características distinto**, y todos puntúan **0,12**.

> **La intensidad no influye en absoluto.** Esa era exactamente la pregunta que
> las tres capturas venían a responder, y está respondida: **no es cuestión de
> velocidad.**

La causa es estructural. Nuestra inundación y el «DDoS» de CICIDS2017 **no son
el mismo ataque**:

| Característica | `hping3 -S` (lab) | `DDoS` (CICIDS2017) |
|---|---|---|
| `flow_duration` | 0,00 | 1.882.981 |
| `tot_fwd_pkts` | 1 | 4 |
| `tot_bwd_pkts` | **0** | 4 |
| `totlen_bwd_pkts` | 0 | 11.601 |
| `bwd_pkt_len_mean` | 0 | 1.934,50 |
| `pkt_len_std` | 0 | 1.903,96 |

La nuestra es una **inundación SYN sin respuesta**: un paquete de ida, nada de
vuelta, duración cero. La suya es una **inundación HTTP contestada**: cuatro
paquetes en cada sentido y 11.601 bytes de respuesta del servidor. Comparten el
nombre y nada más.

**Y el dato decisivo: CICIDS2017 contiene CERO flujos con la firma de nuestra
inundación** (1 paquete de ida, 0 de vuelta). No pocos: ninguno.

> El modelo no está clasificando mal la inundación. Está **extrapolando en una
> región del espacio de características que su entrenamiento nunca cubrió**, y
> un umbral no puede reparar una región que nunca se aprendió.

---

## 3. Qué hacer con la inundación: las opciones, medidas

### Opción A — Que la detecte el SOAR (recomendada)

97.419 flujos en 103 segundos desde una sola IP son **946 flujos por segundo**.
Contar conexiones por IP y por unidad de tiempo detecta eso de forma trivial y
sin ningún modelo.

Encaja con el reparto de trabajo del proyecto y con lo que ya sabíamos: **la
intuición «muchas conexiones = ataque» es correcta por IP y por tiempo, que es
como mide el SOAR, y deja de serlo por flujo, que es lo único que ve el
modelo.** La inundación es precisamente el caso donde el SOAR es el instrumento
adecuado y el modelo no.

**Coste: bajo.** Es una regla de conteo en el componente B, que además ya
necesita esa lógica para la regla de apertura de caso.

### Opción B — Reentrenar incluyendo tráfico del laboratorio

**Viable en volumen, pobre en información.** Tras deduplicar (política D3), las
capturas de ataque aportan:

| Captura | Flujos | **Vectores únicos** |
|---|---|---|
| `syn_1000pps` | 97.419 | **1** |
| `syn_100pps` | 9.607 | **1** |
| `syn_10pps` | 955 | **1** |
| `nmap_rapido` | 1.148 | 100 |
| `nmap_lento` | 92 | 30 |
| `hydra_ssh_250` | 28 | 28 |
| **Total ataque** | 109.249 | **161** |

Frente a los 265.366 flujos de ataque de CICIDS2017. **Entrenar con esto le
enseñaría al modelo un vector concreto**, no un concepto: memorización, no
generalización. Si el atacante cambia de puerto o la trama de relleno cambia,
falla.

A favor: ningún flujo benigno del laboratorio coincide exactamente con el vector
de la inundación (0 de 12.029), así que las clases **sí** son separables. En
contra: rompería el modelo que A4 y A5 validaron y obligaría a repetir toda la
validación, para cubrir un caso que la Opción A resuelve por diseño.

### Opción C — Capturar una inundación que sí se parezca al dataset

Una inundación **HTTP contestada** (`slowhttptest`, `goldeneye`, `ab` a alta
tasa) contra un servidor que responda produciría flujos con payload de vuelta,
que es lo que el modelo aprendió a reconocer.

Es la opción correcta **si la demo tiene que enseñar al modelo detectando la
inundación**. Pero cambia la herramienta del guion, y no arregla el caso
`hping3`: solo lo evita.

**Recomendación: A, y documentar el límite.** Es honesta, encaja con la
arquitectura y no toca un modelo validado. C es complementaria si se quiere que
la demo muestre al modelo actuando sobre una inundación.

---

## 4. Fuerza bruta SSH: sin resolver, y con poca evidencia

28 flujos, mediana 0,24, máximo 0,39. Detectarla exigiría un umbral ≤ 0,25,
donde el **7,4 % del tráfico benigno** se marcaría como ataque. Inviable.

Con 28 flujos tampoco hay base para concluir gran cosa. La captura de `hydra`
con 250 intentos produjo muchos menos flujos de los esperados: conviene revisar
con Frank si `hydra -t 4` reutiliza conexiones. Es el cabo más suelto que queda.

---

## 5. Reproducción

```bash
python src/intelligence/recalibrate.py              # usa la caché de vectores
python src/intelligence/recalibrate.py --re-extract # reextrae (~7 min)
python src/intelligence/threshold.py                # A6, con el punto nuevo
pytest -q                                           # 125 pruebas
```

La extracción de `benigno_hora_punta.pcap` (1,8 GB, 1,7 M paquetes) tarda unos
7 minutos, así que los 24-vectores se cachean en
`data/processed/lab_vectors_v2.parquet`.

`threshold.py` **se niega a ejecutarse si `config.py` no coincide** con la
decisión, de modo que informe y sistema no pueden divergir.

---

## 6. Lo que sigue abierto

1. **La inundación** — decidir entre A y C (§3) con Frank. **Es lo único que
   bloquea la demo.**
2. **La captura de `hydra`** — 28 flujos son pocos; revisar el comando (§4).
3. **Regla de apertura de caso** — cuántos flujos de una IP abren un caso. Con
   1,56 % de falsos positivos sobre tráfico benigno real, es ahora **más**
   importante que antes: es lo que evita que un flujo suelto bloquee a alguien.
4. **Ventanas parciales** — el contrato dice que se evaluarán flujos incompletos
   y el modelo solo ha visto flujos terminados. `pipeline.py` sigue vacío.

---

## 7. Anexo — La primera pasada (v1.0), conservada como registro

> Se conserva porque documenta cómo se detectó el problema y por qué
> hicieron falta capturas nuevas. Sus cifras son de las capturas v1.0,
> tomadas **con el offload activo**, y están superadas por las de arriba.


### 7.1. Lo que se midió

Las 6 capturas del laboratorio pasadas por el extractor de A2 y el Random Forest de
A4, con el punto de operación de A6 leído de `config.py`.

| Captura | Flujos | p mediana | Detección a 0,70 |
|---|---|---|---|
| `benigno_ssh.pcap` | 1 | 0,10 | 0,0 % *(deseado)* |
| `benigno_web.pcap` | 1 | 0,22 | 0,0 % *(deseado)* |
| `portscan_lento_corrected.pcap` | 118 | 0,55 | **6,8 %** |
| `portscan_rapido_corrected.pcap` | 1.147 | 0,54 | **0,9 %** |
| `syn_flood_corrected.pcap` | 100 | 0,22 | **0,0 %** |
| `ssh_bruteforce.pcap` | 3 | 0,28 | **0,0 %** |

---

### 7.2. El diagnóstico que importa: no es un solo problema, son dos

Agrupar todo esto como «la detección es baja» sería un error de análisis. Hay dos
fallos distintos, con causas distintas y dueños distintos.

Detección de cada captura según dónde se ponga el corte:

| Captura | 0,20 | 0,30 | 0,50 | 0,70 | máx. p |
|---|---|---|---|---|---|
| `portscan_lento` | 74,6 % | 74,6 % | **70,3 %** | 6,8 % | 0,72 |
| `portscan_rapido` | 72,3 % | 67,4 % | **58,5 %** | 0,9 % | 0,72 |
| `syn_flood` | 89,0 % | 1,0 % | 0,0 % | 0,0 % | **0,30** |
| `ssh_bruteforce` | 66,7 % | 33,3 % | 0,0 % | 0,0 % | **0,40** |
| `benigno_web` | **100 %** | 0,0 % | 0,0 % | 0,0 % | 0,22 |
| `benigno_ssh` | 0,0 % | 0,0 % | 0,0 % | 0,0 % | 0,10 |

### Problema A — El escaneo: es el umbral

Las probabilidades del escaneo se agrupan en **0,54–0,66**, justo debajo del corte de
0,70. **A 0,50 la detección sube a 58–70 %.** El modelo *sí* reconoce nuestro escaneo:
lo coloca por encima de todo el tráfico benigno disponible (0,10 y 0,22). Lo que falla
es que el corte de A6, calibrado sobre CICIDS2017, queda por encima de donde aterriza
nuestro escaneo. **Esto se arregla moviendo el umbral, y es lo que A7 existe para
hacer.**

### Problema B — La inundación: el modelo no transfiere

`syn_flood` tiene probabilidades entre **0,20 y 0,30**, y `benigno_web` está en
**0,22**. **Se solapan.** No existe ningún umbral que separe nuestro SYN flood del
tráfico benigno: bajar a 0,20 captura el 89 % de la inundación y también el 100 % de
la captura web legítima.

**Esto no lo arregla ningún umbral.** El modelo, sencillamente, no reconoce nuestra
inundación como un ataque.

### Por qué era predecible, y por qué eso importa

`A5_evaluation_note.md` §6.3 dejó escrito, **antes de medir nada de esto**:

> | `nmap -sS -T4` | `PortScan` ya es rápido y ruidoso | **Sí**, el perfil se parece |
> | `hping3 -S` | `DDoS` mide 2,55 pkts/s **por flujo** | **No**: la inundación del laboratorio será mucho más rápida |
>
> «El riesgo se concentra en la inundación, no en el escaneo.»

Es exactamente lo que ocurre. La comparación en el espacio de características lo
confirma: nuestro SYN flood va a **9.554 pkts/s** frente a los **2,55** del `DDoS` de
CICIDS2017 — un factor de **3.748** — y todas sus características de tamaño de
paquete son prácticamente cero frente a valores de miles. **No se parecen en nada.**

La razón de fondo ya está explicada en A5: el `DDoS` de CICIDS2017 son *muchos flujos
escasos* y su caudal solo aparece al agregar por IP; nuestro `hping3` produce flujos
individualmente rapidísimos. Mismo ataque, forma por flujo completamente distinta.

`ssh_bruteforce` también queda por debajo (máx. 0,40), pero **son 3 flujos**: no es
evidencia suficiente para concluir nada. Su perfil de características, en cambio, es
el más cercano a CICIDS2017 de todas las capturas (ratios 1,07–1,55).

---

### 7.3. Un defecto de captura que hay que corregir antes de seguir

Las dos capturas benignas contienen **paquetes de 1.580 y 7.240 bytes**. Un paquete de
7.240 B no viajó así por la red: es la tarjeta de red **fusionando segmentos** antes de
que el capturador los vea (GRO/LRO/TSO).

Importa más de lo habitual aquí: **las tres características más importantes del
modelo son `bwd_pkt_len_mean`, `bwd_pkt_len_std` y `bwd_pkt_len_max`**, y la
coalescencia infla las tres. CICIDS2017 no tiene ese artefacto.

Se corrige **al capturar**, no en el extractor — el extractor debe seguir midiendo lo
que hay en el cable:

```bash
sudo ethtool -K <iface> gro off lro off tso off gso off
```

**Toda captura tomada antes de aplicar esto es sospechosa**, incluidas las dos
benignas actuales. Es una de las razones por las que `benigno_web` puntúa 0,22 en
lugar de bajar más.

---

### 7.4. La otra mitad de A7 sigue bloqueada

A6 §5 dejó como entregable medir la tasa de falsos positivos sobre tráfico benigno del
laboratorio. **Hoy hay 2 flujos benignos en total.**

| Flujos benignos | FP esperados | IC 95 % de la tasa |
|---|---|---|
| **2** *(lo que hay)* | 0,0 | [0,00022 – **0,66742**] |
| 1.000 | 1,9 | [0,00021 – 0,00537] |
| 5.000 | 9,4 | [0,00088 – 0,00327] |
| **10.000** | 18,9 | [0,00114 – 0,00283] |

El intervalo actual va del 0,02 % al 67 %: no distingue un detector que funciona de
uno que bloquea a dos de cada tres usuarios. **Y es el número sobre el que descansa
toda la decisión de contención.**

Más sesiones SSH no lo arreglan: A2 §5 ya avisó de que las capturas benignas son
sesiones únicas y largas — un SSH = **1 flujo**. Hacen falta miles de flujos benignos,
lo que exige tráfico sostenido y variado de varios equipos.

---

### 7.5. Alcance de A7: recalibrar es mover el umbral, no reentrenar

`A1_analysis_and_decisions.md` §9 redactó A7 como «el modelo **aprende** el patrón real
de nuestro laboratorio», lo que se lee como reentrenar. **Queda zanjado aquí: A7 mueve
el umbral, no reentrena.**

- Reentrenar con unos miles de flujos del laboratorio frente a 1,6 M de CICIDS2017
  descartaría el modelo que A4 y A5 validaron y obligaría a repetir la validación
  entera.
- Y no arreglaría el problema B: si nuestro SYN flood no se parece a ningún `DDoS` del
  dataset, lo que hace falta es **más y mejor tráfico propio**, no un ajuste fino sobre
  las 3 capturas que tenemos.

---

### 7.6. Reproducción

```bash
python src/intelligence/lab_calibration.py   # ~2 min, ningun reentrenamiento
pytest -q                                    # 125 pruebas
```

Lee los pcaps de `data/pcap/`, el modelo de `models/` y las medianas por familia de
`data/processed/train.parquet`. Reutiliza `extract_all` de `scripts/profile_pcap.py`,
que es la extracción que A2 validó — una segunda copia acabaría divergiendo.

---

### 7.7. Qué queda, en orden

1. **Capturas nuevas de Frank, con el offload desactivado.** Es el bloqueo real. Sin
   miles de flujos benignos no se puede fijar ningún umbral con fundamento, y sin una
   inundación mejor caracterizada no se puede saber si el problema B es del modelo o
   de la captura.
2. **Recalibrar el umbral** con esas capturas. La evidencia actual apunta a bajarlo
   hacia **0,50**, que recuperaría 58–70 % del escaneo. Pero **no se puede fijar sin
   medir antes los falsos positivos**: A6 §5 ya mostró que bajar de 0,70 a 0,50 sube
   los falsos positivos de 189 a 228 por cada 100.000 flujos benignos *en CICIDS2017*,
   y en el laboratorio no tenemos ese número.
3. **Si el umbral baja de 0,70**, revisar `SEV_MEDIUM` y `SEV_HIGH` con Frank — A1 §9.
4. **Decidir qué hacer con el problema B.** Opciones, por coste creciente: aceptar que
   la inundación se detecta por el SOAR (que sí cuenta conexiones por IP y por tiempo,
   que es como una inundación *sí* se distingue) en lugar de por el modelo; o capturar
   inundaciones más parecidas al perfil del dataset. **La primera es la que encaja con
   el diseño**: el modelo aporta la forma del flujo, el SOAR aporta el caudal.
5. **Ventanas parciales** y **regla de apertura de caso**: siguen abiertas, son del
   componente B, y `src/system/pipeline.py` sigue vacío.
