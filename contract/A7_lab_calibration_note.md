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
> - **Fuerza bruta SSH:** marginal, y la captura no contiene los 250 intentos
>   pedidos (§7.1). Hay que repetirla.
> - **Ataque lento (`slowloris`):** **no existe ninguna captura.** Es el
>   escenario 3 de la demo y el nombre engaña — `nmap_lento` es un *escaneo*
>   lento, no un ataque lento (§7.2).
> - **Reparto final:** el modelo cubre escaneo y ataque lento; el SOAR cubre la
>   inundación con una regla de tasa por IP. Medido en §6.

---

## 0. Las tres pasadas

| | Primera pasada | Segunda pasada |
|---|---|---|
| Capturas | `data/pcap/pcap_v1.0/` | `data/pcap/pcap_v2.0/` |
| Flujos benignos | **2** | **12.029** |
| Offload de la tarjeta | activo (tramas de 7.240 B) | **desactivado** (máx. 1514 B) |
| Módulo | `lab_calibration.py` | `recalibrate.py` |
| Resultado | diagnóstico, sin poder decidir | **umbral fijado** |

Y una **tercera pasada** (§12), sobre las capturas `pcap_v2.1` que Frank tomó para
los cuatro escenarios de la demo: inundación HTTP, `slowloris`, cuerpo lento y
fuerza bruta SSH. Módulo `validate_lab_attacks.py`. Resultado: **el umbral no
cambia, y el modelo solo detecta el escaneo** — el resto lo cubre el SOAR, salvo
la fuerza bruta SSH (§13).

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

## 6. El reparto del trabajo: qué detecta el modelo y qué el SOAR

La inundación deja de ser problema del modelo y pasa a ser del SOAR. Eso no es
una renuncia: es que **el caudal solo existe al agregar por IP**, y el modelo ve
un flujo aislado por diseño (la identidad está excluida del contrato por fuga de
datos, A1 §6.3).

Lo que el SOAR sí puede contar, medido sobre las capturas reales — **conexiones
nuevas por IP de origen en ventanas de 10 segundos**:

| Captura | Media / ventana | **Máximo / ventana** |
|---|---|---|
| `benigno_hora_punta` | 23,5 | **300** |
| `benigno_tranquilo` | 5,5 | 18 |
| `ataque_nmap_lento` | 1,0 | **1** |
| `ataque_nmap_rapido` | 577,5 | 1.148 |
| `ataque_syn_10pps` | 52,8 | **102** |
| `ataque_syn_100pps` | 485,4 | 1.006 |
| `ataque_syn_1000pps` | 4.433,1 | 9.473 |

### La regla propuesta para el componente B

> **Más de 500 conexiones nuevas desde una misma IP en 10 segundos → caso de
> severidad ALTA, sin consultar al modelo.**

El 500 sale de la medición: el máximo benigno observado es **300** en una
ventana, y el ataque más flojo que la regla debe capturar produce **1.006**. El
hueco entre ambos es suficiente para no afinar el número.

### El reparto medido, y por qué los dos hacen falta

| Ataque | Modelo (0,50) | Regla de tasa (>500/10 s) |
|---|---|---|
| `nmap` lento | **66,3 %** ✅ | 0 % ❌ (máximo 1 por ventana) |
| `nmap` rápido | 56,4 % ✅ | ✅ (1.148) |
| `syn` 1000 pps | 0 % ❌ | ✅ (9.473) |
| `syn` 100 pps | 0 % ❌ | ✅ (1.006) |
| `syn` 10 pps | 0 % ❌ | ❌ (102, dentro del ruido benigno) |

**Son complementarios y ninguno sobra.** El escaneo lento es invisible para la
regla de tasa —produce **1 conexión por ventana**— y el modelo lo detecta al
66 %. La inundación es invisible para el modelo y la regla la ve sin esfuerzo.
Ese es exactamente el argumento arquitectónico del proyecto, ahora con cifras:
**el modelo aporta la forma del flujo, el SOAR aporta el caudal por IP.**

### El hueco honesto

`syn_10pps` **no lo detecta ninguno de los dos**: 102 conexiones por ventana
queda por debajo del máximo benigno de 300. Conviene decirlo antes de que lo
pregunten, junto con el matiz que lo relativiza: **10 paquetes por segundo no
son una denegación de servicio**. Ese caudal no tumba nada; es ruido con forma
de inundación. La captura se pidió para responder «¿es cuestión de
intensidad?», y respondió que no.

### Lo que hay que añadir a `config.py`

Hoy no existe ningún parámetro de tasa. Habría que añadir algo como:

```python
# --- Correlación por IP (componente B) ---
RATE_WINDOW_SECONDS   = 10    # ventana de conteo
RATE_FLOWS_THRESHOLD  = 400   # conexiones nuevas por IP -> caso ALTO
```

**El 400 es una corrección de la tercera pasada.** Propuse 500 aquí, pero luego se
midió que `slowloris` abre 486 conexiones por ventana (§12.2), y con 500 quedaría
fuera. Con el máximo benigno en 300, un umbral de **400** separa `slowloris` (486)
del ruido benigno con margen de 100 a cada lado. Es más estrecho que para el SYN
flood, pero funciona. **Son de Frank**, no míos: los mido y los propongo, los fija
quien implementa la correlación.

---

## 7. Lo que falta capturar

### 7.1 Fuerza bruta SSH — sí, hace falta repetirla

La captura actual **no contiene los 250 intentos pedidos**. Sus 28 flujos se
parten en dos grupos:

| Grupo | Flujos | Paquetes | Duración | Probabilidad |
|---|---|---|---|---|
| Sesiones SSH completas | **12** | 39 | 14–21 s | 0,12–0,39 |
| Conexiones rechazadas | **15** | 9 | **~1 ms** | 0,16–0,29 |
| Otra | 1 | 22 | 0,09 s | 0,02 |

Los 15 flujos de **1 milisegundo** son conexiones que el servidor aceptó y cortó
en el acto: la víctima corre **OpenSSH 10.2** y sus límites `MaxStartups` y
`MaxAuthTries` estrangulan el ataque. Las 12 sesiones buenas son **idénticas
entre sí**, así que hydra repitió doce veces lo mismo. En total 625 paquetes,
cuando 250 intentos SSH reales necesitarían varios miles.

**Y aun así, ninguna llega a 0,50.** Las de 39 paquetes se quedan en 0,39. La
`SSH-Patator` de CICIDS2017 son sesiones de 53 paquetes y **12 segundos con
muchos intentos dentro de una misma conexión**; las nuestras son 39 paquetes con
un intento. Es el mismo desajuste que la inundación, pero **mucho más leve y
probablemente recuperable con una captura mejor** — de ahí que sí merezca la
pena repetirla, mientras que en la inundación no.

### 7.2 Ataque lento — no existe ninguna captura, y es escenario de la demo

**Esto no estaba detectado hasta ahora y conviene dejarlo escrito con claridad,
porque el nombre engaña.**

`nmap_lento` y `portscan_lento` son **escaneos lentos**: pertenecen a la familia
`PortScan` y el modelo los detecta al 66,3 %. **No son «ataques lentos».**

En el vocabulario del proyecto (A1 §9) «ataque lento» es **`DoS slowloris`**:
mantener muchas conexiones HTTP abiertas enviando lo mínimo para que no se
cierren. Es un ataque distinto, de una familia distinta, **y no hay ninguna
captura de él en el laboratorio.**

Los cuatro escenarios de la demo, según A1 §9, y su estado real:

| # | Escenario | Familia | Captura | Estado |
|---|---|---|---|---|
| 1 | Escaneo rápido y lento | `PortScan` | ✅ | **Resuelto** — 56–66 % |
| 2 | Inundación | `DDoS` | ✅ | **Al SOAR** (§6) |
| 3 | **Ataque lento** | `DoS slowloris` | ❌ **no existe** | **Sin capturar** |
| 4 | Fuerza bruta SSH | `SSH-Patator` | ⚠️ parcial | Repetir (§7.1) |

Que falte el escenario 3 importa más de lo que parece: **`slowloris` es la
familia donde el modelo mejor rinde** (0,9926 de recall sobre CICIDS2017) y
donde la regla de tasa del SOAR **no puede ayudar** — un slowloris abre pocas
conexiones y las mantiene, así que su caudal por IP es bajo. Es el escenario que
mejor demuestra por qué hace falta un modelo, y es el único que no se ha
capturado.

Además hay una razón para esperar que transfiera bien: CICIDS2017 generó su
`slowloris` con **la misma herramienta** que usaríamos nosotros, a diferencia de
la inundación, donde el dataset usó un flood HTTP contestado y nosotros un SYN
al vacío.

> **⚠ REFUTADO por la tercera pasada (§12).** Esta predicción resultó falsa en
> sus dos mitades. El modelo detecta el `slowloris` real al **0 %**, y la regla
> de tasa del SOAR **sí** puede ayudar. Las dos razones están en §12.2. Se
> conserva el texto para que se vea qué se predijo y qué se midió.

---

## 8. Ventanas parciales — revisadas sobre el código real

`src/system/pipeline.py` **ya no está vacío**: está en la rama `soar-response`, y
las ventanas parciales **ya están implementadas**. En `src/system/capture.py`:

```python
# PARTIAL WINDOW
if flow.packet_count % config.WINDOW_SIZE == 0:
    self.process_inference(flow)
```

Con `WINDOW_SIZE = 100`, cada 100 paquetes se puntúa el flujo **incompleto**. Es
uno de los cuatro puntos donde se llama al modelo, junto con el cierre por
FIN/RST, el timeout activo y el timeout de inactividad.

### El hallazgo: con 100 paquetes, la ventana solo se dispara sobre tráfico benigno

Paquetes por flujo, medido:

| Familia | p50 | p95 | **% con ≥ 100 paquetes** |
|---|---|---|---|
| BENIGN | 4 | 47 | **1,73 %** |
| SSH-Patator | 53 | 55 | 0,00 % |
| FTP-Patator | 24 | 24 | 0,00 % |
| DoS Hulk | 13 | 16 | 0,00 % |
| DoS GoldenEye | 11 | 16 | 0,00 % |
| DDoS | 8 | 14 | 0,00 % |
| DoS Slowhttptest | 7 | 10 | 0,00 % |
| DoS slowloris | 4 | 19 | 0,00 % |
| PortScan | 4 | 8 | 0,06 % |

> **Ninguna familia de ataque alcanza los 100 paquetes.** El 0,00 % de los flujos
> de ataque de CICIDS2017 los supera, y el 0,00 % de los del laboratorio (máximo
> observado: **39**).

En el tráfico benigno del laboratorio, en cambio, **el 9,16 % de los flujos pasa
de 100 paquetes** y generarían **12.962 evaluaciones parciales** — más que los
12.029 flujos completos. La ventana parcial **duplica las llamadas al modelo, y
todas las añadidas son sobre tráfico legítimo.**

**Tal como está configurada hoy, la ventana parcial es superficie de falsos
positivos con cero beneficio de detección.**

### El problema de fondo: el disparador cuenta lo que no debe

La ventana parcial existe por una razón legítima: **detectar antes de que el
flujo termine**. Un `slowloris` mantiene una conexión abierta ~100 segundos, y
con `ACTIVE_TIMEOUT = 120` esperar al cierre significa detectarlo dos minutos
tarde.

Pero el disparador cuenta **paquetes**, y los ataques que necesitan detección
temprana son **lentos por definición**: no acumulan paquetes. `slowloris` manda 4
paquetes de mediana. **Un contador de paquetes no se dispara nunca en el caso
para el que se diseñó.**

### Qué hacer, en dos pasos

1. **Ahora: que la ventana parcial no abra casos.** O se desactiva, o su
   resultado va a `monitor` y no a `enforce`. La evidencia es inequívoca: el
   0,00 % de los ataques llega a dispararla.
2. **Después de capturar `slowloris` (§7.2): decidir un disparador por TIEMPO**,
   no por paquetes — puntuar los flujos abiertos cada N segundos. Esa es la forma
   correcta de detectar temprano un ataque lento.

**Pero eso arrastra un desajuste que sigue sin medir:** el modelo solo ha visto
flujos **terminados**. Un flujo puntuado a los 30 segundos tiene otra duración,
otros estadísticos IAT y otras tasas que el mismo flujo al cerrarse. Se puede
medir troceando un pcap por tiempo y comparando, **y hay que hacerlo antes de
activar ninguna ventana temporal.** Con la captura de `slowloris` se puede medir
lo uno y lo otro a la vez.

### Aviso: `config.py` ha divergido entre ramas

| Campo | `ia-model` | `soar-response` |
|---|---|---|
| `THRESHOLD` / `SEV_MEDIUM` | **0,50** | 0,70 |
| `SEV_HIGH` | **0,70** | 0,90 |
| `WINDOW_SIZE` | — | 100 |
| `CAPTURE_INTERFACE`, `BPF_FILTER` | — | presentes |

Al fusionar hay que conservar **las dos mitades**: el umbral recalibrado de A7 y
los campos de captura del componente B. Si la fusión se resuelve tomando un lado
entero, o el sistema corre con el umbral viejo o pierde la configuración de
captura.

---

## 9. Falta una captura más: inundación HTTP contestada

En §2 quedó demostrado que el modelo no ve nuestra inundación SYN porque
CICIDS2017 no contiene ningún flujo con esa forma. De ahí salió una afirmación
que **es una inferencia, no una medición**:

> «Si la demo lanzara una inundación HTTP contestada, el modelo probablemente sí
> la vería, porque el `DDoS` de CICIDS2017 —que es exactamente eso— se detecta al
> 0,9990.»

**Eso hay que comprobarlo, y es barato.** Es la diferencia entre dos frases muy
distintas en la defensa:

- «El modelo no detecta inundaciones.» — concede mucho más de lo que la evidencia
  sostiene.
- «El modelo detecta inundaciones HTTP; no detecta una inundación SYN sin
  respuesta, porque el dataset no contiene ninguna.» — es lo que creemos, y hoy
  no está probado.

Una captura de inundación HTTP contra un servidor que responda cierra la
pregunta en un sentido o en otro:

- **Si se detecta:** valida el 0,9990 sobre tráfico propio, y la demo gana una
  inundación que **el modelo y el SOAR detectan a la vez**, cada uno por su
  camino. Es el escenario más sólido posible.
- **Si no se detecta:** es un resultado negativo importante — significaría que el
  desfase de dominio es más profundo que un desajuste de tipo de ataque, y habría
  que decirlo.

Cualquiera de los dos resultados es publicable. Que la predicción sea falsable es
justamente lo que la hace útil.

> **⚠ MEDIDO en la tercera pasada (§12).** Ni lo uno ni lo otro del todo: el
> modelo detecta la inundación HTTP al **3,8 % por flujo**, no al 99 %, pero
> como **caso** se detecta con certeza (958 de 25.068 flujos superan el corte).
> El detalle en §12.1.

---

## 12. Tercera pasada (v2.1) — el modelo contra los ataques que faltaban

Frank capturó las cuatro que pedimos: inundación HTTP contestada, `slowloris`,
cuerpo lento y fuerza bruta SSH repetida. Todas con el offload desactivado
(trama máxima 1514 B). **El resultado obliga a corregir dos predicciones que esta
misma nota había hecho razonando desde CICIDS2017.**

Veredicto al punto de operación vigente (0,50):

| Captura | Familia | Flujos | p50 | máx | Det. 0,50 | Veredicto |
|---|---|---|---|---|---|---|
| `http_flood_ab` | DDoS | 25.068 | 0,01 | 1,00 | 3,8 % | Parcial (por caso) |
| `slowloris` | DoS slowloris | 513 | 0,00 | 0,07 | 0,0 % | **No detectado** |
| `slowbody_ab` | DoS Slowhttptest | 511 | 0,00 | 0,04 | 0,0 % | **No detectado** |
| `ssh_bruteforce_ab` | SSH-Patator | 30 | 0,12 | 0,15 | 0,0 % | **No detectado** |

**El umbral no se toca.** Ninguna se separa del tráfico benigno bajando el
corte: a 0,10, `slowloris` y `slowbody` siguen en 0 % mientras el tráfico
benigno ya marca 10 % de falsos positivos. No es un problema de umbral.

### 12.1 Inundación HTTP — la predicción de §9, medida

Predije que se detectaría «probablemente al 99 %», por analogía con el `DDoS` de
CICIDS2017. **Medido: 3,8 % por flujo.** Nuestra inundación `ab` es mucho más
corta (42 ms de mediana frente a 1,9 s) y con menos respuesta del servidor, así
que cae por debajo de donde vive el `DDoS`.

**Pero como caso se detecta con certeza:** 958 de sus 25.068 flujos superan el
corte, y con la agrupación del SOAR la probabilidad de perder el ataque entero es
0. Y además su tasa por IP es **19.203 conexiones / 10 s**, muy por encima de la
regla de tasa. **Queda cubierta dos veces**, por el modelo (a nivel de caso) y
por el SOAR.

> La afirmación correcta no es «el modelo detecta inundaciones HTTP», sino **«las
> detecta a nivel de caso, no de flujo»**. Es una concesión menor que «no las
> detecta», y ahora está medida, no inferida.

### 12.2 `slowloris` y cuerpo lento — la predicción de §7.2, refutada entera

Había escrito que `slowloris` era donde el modelo mejor rinde y donde el SOAR no
podía ayudar. **Las dos mitades son falsas**, y las dos por la misma causa: el
servidor **responde**.

| `slowloris` | Laboratorio | CICIDS2017 |
|---|---|---|
| `totlen_bwd_pkts` | 453 | **0** |
| `bwd_pkt_len_mean` | 64,71 | **0** |
| `pkt_len_std` | 120,58 | 4,62 |

El `slowloris` de CICIDS2017 golpeó un servidor que **se quedaba mudo** —cero
bytes de vuelta—, y el modelo aprendió esa forma. Nuestra víctima corre Apache,
que **contesta con un 400** a la petición a medias, así que el flujo lleva bytes
de respuesta. Misma herramienta, comportamiento del servidor distinto → vector
distinto → el modelo no lo reconoce.

Y la otra mitad: **`slowloris` abre muchas conexiones** —486 por IP cada 10 s en
esta captura—, no pocas. Eso **sí** lo ve la regla de tasa del SOAR. La detección
del ataque lento acaba siendo trabajo del SOAR, no del modelo — justo lo
contrario de lo que predije.

Esto tiene una consecuencia para la regla de tasa (§6): con `slowloris` a 486 y
el máximo benigno en 300, el umbral de **500 que propuse deja fuera el
`slowloris`**. Habría que bajarlo a **~400** (300 benigno < 400 < 486 slowloris),
con el aviso de que el margen es más estrecho que para el SYN flood.

### 12.3 Fuerza bruta SSH — la captura salió bien, y aun así 0,12

La nueva captura sí contiene el ataque: 606 intentos SSH reales, 30 flujos con
sesiones completas (frente a los 28 con basura de la v2.0). Y sus **tamaños de
paquete son casi idénticos** a los de CICIDS2017:

| `ssh_bruteforce_ab` | Laboratorio | CICIDS2017 | ratio |
|---|---|---|---|
| `tot_fwd_pkts` | 21 | 21 | 1,00 |
| `totlen_bwd_pkts` | 2.522 | 2.745 | 0,92 |
| `bwd_pkt_len_mean` | 84,07 | 85,78 | 0,98 |
| `fwd_act_data_pkts` | 16 | 16 | 1,00 |
| **`flow_duration`** | 31.163.142 | 12.044.221 | **2,59** |
| **`flow_iat_mean`** | 626.420 | 231.353 | **2,71** |
| **`flow_pkts_s`** | 1,63 | 4,41 | 0,37 |

**Los tamaños coinciden; los tiempos no.** Nuestra fuerza bruta es 2,6 veces más
lenta por flujo. `SSH-Patator` fue siempre la familia más frágil del modelo (A1
§9 la medía a 0,50), la única que se apoyaba en características que descartamos por
huella de entorno. Que un desajuste de ritmo la tumbe del todo es coherente con
esa fragilidad.

Es el caso más recuperable de los tres: la forma es correcta, solo el ritmo
difiere. Un `hydra -t 16` (más paralelo, intentos más rápidos) podría acercarlo.
Pero es incierto, y son solo 30 flujos.

---

## 13. Qué significa esto para la demo

Estado real de los cuatro escenarios, ya medido sobre tráfico propio:

| # | Escenario | ¿Modelo? | ¿SOAR (tasa)? | Cubierto |
|---|---|---|---|---|
| 1 | Escaneo (`nmap`) | ✅ 56–66 % | ❌ (lento: 1/10 s) | **Sí, modelo** |
| 2 | Inundación SYN (`hping3`) | ❌ 0 % | ✅ (9.473/10 s) | **Sí, SOAR** |
| 2b | Inundación HTTP (`ab`) | ⚠ por caso | ✅ (19.203/10 s) | **Sí, ambos** |
| 3 | Ataque lento (`slowloris`) | ❌ 0 % | ✅ (486/10 s, umbral a 400) | **Sí, SOAR** |
| 4 | Fuerza bruta SSH (`hydra`) | ❌ 0,12 | ❌ (pocas conexiones) | **NO** |

**El hallazgo incómodo y honesto: el modelo, sobre tráfico del laboratorio, solo
detecta el escaneo.** Todo lo demás lo cubre el SOAR por tasa, salvo la fuerza
bruta SSH, que **hoy no cubre nadie**.

Esto **no invalida el proyecto**, pero cambia el guion de la defensa y hay que
decirlo sin adornos:

1. **El sistema completo detecta 3 de los 4 escenarios**, repartidos entre modelo
   y SOAR. Ese reparto es exactamente la arquitectura que el proyecto defiende: el
   modelo aporta la forma, el SOAR aporta el caudal.
2. **El valor del modelo se concentra en lo que el conteo no puede ver:** el
   escaneo lento (1 conexión cada 10 s) y, sobre CICIDS2017, las familias que sí
   coinciden. Un IDS de solo-reglas no vería el escaneo lento.
3. **El desfase de dominio es real y está cuantificado.** Dos de las cuatro
   capturas refutaron predicciones que parecían razonables. Ese es el riesgo que
   A1 marcó como principal, ahora con números — y es más honesto presentarlo que
   esconderlo.
4. **La fuerza bruta SSH es el hueco abierto.** Es recuperable (la forma coincide,
   falla el ritmo), pero hoy no está resuelto.


### 13.1 Decisiones tomadas sobre los dos huecos

**`slowloris` → SOAR, y NO se fabrica tráfico a medida.** El experimento de §12.2
mostró que el modelo detectaría un `slowloris` al 97 % **si** el servidor no
respondiera y las conexiones enviaran lo mínimo (como en CICIDS2017). Se **descarta**
hacer esa captura: exige un servidor mudo artificial (un `iptables` que descarte la
respuesta) y conexiones recortadas, es decir, construir en el laboratorio un flujo con
las características del dataset. Eso fuerza la demo y no demuestra generalización.
`slowloris` abre 486 conexiones/10 s, así que **lo cubre la regla de tasa del SOAR**
sin artificios. El argumento del valor del modelo lo lleva el **escaneo lento** (1
conexión/10 s, que el SOAR no puede ver y el modelo detecta al 66 %), que es un caso
limpio y no requiere configurar nada.

**Fuerza bruta SSH → regla de tasa en el puerto :22 (nueva).** Ni el modelo (0,12) ni
la regla de tasa general la detectan. Pero el tráfico benigno del laboratorio tiene
**cero conexiones al puerto 22**, así que una regla que cuente conexiones nuevas al
:22 por IP, con umbral bajo (10/60 s), la detecta sin falsos positivos. Es el enfoque
`fail2ban` a nivel de red. La captura actual queda al borde (9/60 s con `hydra -t 4`),
así que se pide recapturar con `MaxAuthTries 2` + `hydra -t 16` para que genere ~125
conexiones en vez de 30. El modelo se da por perdido para SSH: falla por ritmo y era
su familia más frágil. Requerimientos completos en
`Documents/requerimientos_frank_v4.md`.

**Objeción prevista (y su respuesta medida): ¿bloquearía un SSH legítimo?** No. La
regla tiene umbral (>10 conexiones al :22 por IP en 60 s), no bloquea una conexión
suelta. Medido: un login SSH benigno es **1 conexión** (y dura 12,7 s con 631 paquetes
de sesión real); la fuerza bruta son **30** (→ ~125 tras recaptura). Un admin que
falla y reconecta 2-3 veces sigue diez veces por debajo del umbral. La **duración no
distingue** —`hydra` mantiene la conexión ~31 s, más que el login benigno—, así que la
regla se apoya solo en el conteo, que sí separa. Refuerzo: la `WHITELIST` de
`config.py` exime a las IPs de administración conocidas.

---

## 14. Lo que sigue abierto

Por orden de lo que bloquea la demo:

1. **Regla de tasa general por IP en el SOAR** — umbral **400 / 10 s** (§6, §13.1).
   Cubre inundación SYN, inundación HTTP, escaneo rápido y `slowloris`.
2. **Regla de tasa en el puerto :22** — umbral **10 / 60 s** (§13.1). Cubre la
   fuerza bruta SSH; el benigno del lab da 0 conexiones al :22.
3. **Recapturar la fuerza bruta SSH** — `MaxAuthTries 2` + `hydra -t 16`, para que
   la regla del punto 2 dispare con margen (§13.1).
4. **Que la ventana parcial deje de abrir casos** — §8. Hoy solo se dispara
   sobre tráfico benigno.
5. **Regla de apertura de caso** — cuántos flujos de una IP abren un caso.
6. **Fusionar `config.py`** conservando las dos mitades — §8.
7. **Medir el desajuste de las ventanas temporales** antes de activarlas — §8.

Los puntos 1–3 están en `Documents/requerimientos_frank_v4.md`.

**Lo que ya NO queda pendiente** (cerrado en la tercera pasada): capturar
`slowloris`, capturar la inundación HTTP, y repetir la fuerza bruta SSH. Las tres
se capturaron y midieron; el resultado está en §12.

Petición de capturas para Frank: `Documents/requerimientos_frank_v3.md` (cumplida).

---

## 15. Anexo — La primera pasada (v1.0), conservada como registro

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
