# Tarea A1 — Análisis y decisiones del contrato de características

**Documento interno del equipo.** Para Sebastián (Persona A) y Frank (Persona B).
Explica *por qué* el contrato quedó como quedó. La especificación formal está en
`contract/contract_characteristics.md`.

Fecha: agosto 2026 · Rama: `ia-model` · Estado: cerrado, pendiente de validación en A2

---

## 0. Resumen en cinco líneas

- Auditamos los 8 CSV completos de CICIDS2017: **2.830.743 flujos, 78 columnas de características**.
- De esas 78 sobreviven **51** tras filtrar identidad, constantes, duplicados, columnas irreproducibles en vivo y huellas del entorno.
- Medimos que **24 características capturan el 99,96% del rendimiento** que dan las 51. Por eso 24 no es un capricho.
- **Las 5 banderas TCP salen del contrato**: el CSV no mide lo que su nombre dice, y nuestro extractor no puede reproducir el error.
- **La ventana TCP inicial también sale**, aunque sube el F1 tres puntos, porque identifica el sistema operativo del atacante y en nuestro laboratorio las dos VM son Fedora.

Todo lo que sigue es reproducible con `python src/intelligence/audit_dataset.py`.

---

## 1. Qué es un contrato de características y por qué existe

El modelo no ve tráfico. Ve una lista de 24 números.

Imagina una máquina expendedora con 24 ranuras numeradas. La ranura 1 espera la
duración del flujo, la 2 el número de paquetes de ida, y así. El modelo aprendió
durante el entrenamiento qué significa cada ranura.

Si en la demo metemos 25 números, o metemos la duración en la ranura 2, la máquina
**no da error**. Devuelve una respuesta con total confianza, y esa respuesta está mal.
Ese es el fallo silencioso que arruina este tipo de proyectos.

Por eso el contrato fija tres cosas que nadie puede cambiar unilateralmente:

1. **Cuántas** características (24).
2. **Cuáles** y en **qué orden** (posiciones 0 a 23, congeladas).
3. **Qué significa exactamente cada una**: unidad, fórmula, qué hacer si sale NaN.

El punto 3 es el que casi se nos escapa. Dos columnas pueden llamarse igual y medir
cosas distintas. Esta tarea consistió, sobre todo, en descubrir dónde pasaba eso.

### Qué significa esto para Frank

Frank llama a dos funciones y no necesita saber nada más:

```python
from intelligence.extractor import extract_features
from intelligence.model import predict

vector = extract_features(flow)   # siempre 24 floats, siempre en el mismo orden
p = predict(vector)               # probabilidad de ataque, 0.0 a 1.0
```

Todas las conversiones de unidades viven **dentro** de `extract_features`. Frank no
ve microsegundos ni bytes de cabecera: recibe 24 números ya listos. Si mañana
cambiamos una conversión, su código no se entera.

**Lo único que rompe a Frank es cambiar el número 24 o el orden.** Si eso llega a
pasar, el contrato sube de versión y se avisa explícitamente.

---

## 2. El problema de fondo: dos caminos que deben coincidir

```
CAMINO A — entrenamiento          CAMINO B — demo en vivo
CICIDS2017 (CSV ya calculado)     pcap de Frank
            │                                │
            │                        nuestro extractor
            │                                │
            └──────────→ MODELO ←────────────┘
```

El modelo aprende del camino A y trabaja en el camino B. Si los dos caminos calculan
las cosas de forma distinta, el modelo recibe en la demo algo que no se parece a lo
que aprendió.

El CSV de CICIDS2017 fue generado en 2017 con **CICFlowMeter en Java**. Nuestro
extractor usa **cicflowmeter en Python**, que es una reimplementación distinta. Los
nombres de las columnas se parecen. Los números, no siempre.

Encontramos **cuatro clases de problema**, y separarlas fue lo que desatascó la tarea:

| | Problema | ¿Se puede arreglar? |
|---|---|---|
| **P1** | Distinta unidad o escala | Sí, con una conversión exacta |
| **P2** | La columna no mide lo que dice | No: habría que replicar un bug ajeno |
| **P3** | La columna mide el entorno, no el ataque | No sirve, aunque sea reproducible |
| **P4** | Columnas constantes, duplicadas o con infinitos | Se descartan o se les define un tratamiento |

---

## 3. P1 — Diferencias de unidad (resolubles)

### 3.1 El tiempo está en microsegundos

En el CSV, `Flow Duration` tiene mediana 31.253 y máximo 120.000.000.

Si fueran segundos, el flujo más largo habría durado casi 4 años. Con un *timeout*
activo de 120 segundos, ese máximo de 1,2×10⁸ solo tiene sentido en **microsegundos**.

Nuestro extractor devuelve segundos: en la prueba de humo, un flujo de 60 ms dio `0.06`.

**Factor 10⁶.** Afecta a 7 de las 24 características (duración y todos los IAT).

*Por qué importa:* el Random Forest aprende cortes como «duración < 850.000». Si en
vivo los valores llegan entre 0 y 100, **todos** los flujos caen del mismo lado de
**todos** los cortes. El modelo no falla: responde casi lo mismo para todo.

### 3.2 Los tamaños de paquete son payload, no trama

En los 33.150 flujos de PortScan, `Fwd Packet Length Max` tiene **mediana 0**.

Un escaneo SYN no lleva datos: solo cabeceras. Que el CSV diga 0 significa que mide
**el payload** — los bytes de datos, sin cabeceras.

Nuestro extractor devolvió **54** para ese mismo SYN: 14 de Ethernet + 20 de IP +
20 de TCP. Mide **la trama completa**.

Afecta a 12 de las 24 características.

> **Detalle curioso, útil para la defensa.** Algunas sondas de nmap muestran valor 2
> en lugar de 0. Es porque la sonda con opciones TCP suma 44 bytes IP, pero Ethernet
> exige tramas de al menos 60, así que la tarjeta rellena con 2 bytes de padding. El
> CICFlowMeter de Java los cuenta como si fueran datos. O sea que el CSV no solo mide
> distinto: arrastra ruido de la capa física.

### 3.3 Cómo se resuelve: el extractor se degrada hacia el CSV

Esta fue la decisión de arquitectura más importante de la tarea, y **no es cuestión
de comodidad**.

Podríamos convertir el CSV al espacio del extractor, o el extractor al espacio del
CSV. Parecen simétricas. No lo son:

| | Extractor → espacio CSV | CSV → espacio extractor |
|---|---|---|
| Tiempo | dividir entre 10⁶ | multiplicar por 10⁶ |
| Tamaños | medir payload en vez de trama | **imposible**: reconstruir cabeceras y padding desde el payload |

**El extractor tiene información más rica; el CSV la perdió.** No hay operación que
recupere lo destruido. Solo se puede ir de rico a pobre.

Nota importante sobre cómo se implementa: no restamos 54 bytes a posteriori. Como
controlamos el código del extractor, **cambiamos la medición**: donde el extractor
usaba `len(packet)`, usará la longitud del payload. La conversión es exacta, no
aproximada. Lo mismo con el tiempo: se emite en microsegundos directamente.

---

## 4. P2 — Las banderas TCP no miden banderas TCP

### 4.1 Qué son y por qué las queríamos

Cuando dos máquinas hablan por TCP, cada paquete lleva casillas marcadas que indican
qué tipo de mensaje es:

- **SYN** — quiero conectarme
- **ACK** — recibido
- **FIN** — termino ordenadamente
- **RST** — cierro de golpe (o este puerto está cerrado)
- **PSH** — entrega estos datos ya

Un escaneo de puertos es casi todo SYN y RST sin ACK. Un SYN flood es SYN que nunca
se completa. Es información valiosa, y por eso estaban en la propuesta original.

### 4.2 Lo que NO es una razón para descartarlas

Frank planteó, con razón, que **«solo tienen valores 0 y 1» no demuestra nada**. Es
correcto y hay que dejarlo claro:

- Sí, las cinco columnas solo toman 0 y 1 en los 2,8 millones de filas.
- Eso significa que son **indicadores de presencia**, no conteos. Es una decisión de
  diseño perfectamente válida.
- Una variable binaria puede ser utilísima para un modelo.

También hubo un error de análisis por nuestra parte que conviene registrar: al
principio se afirmó que estas columnas separaban PortScan del tráfico benigno de
forma perfecta y que eso era fuga de datos. Se midió y es falso:

| Prueba | F1 |
|---|---|
| Solo las 5 banderas → ataque vs. benigno | **0,099** |
| Solo las 5 banderas → PortScan vs. BENIGN | **0,000** |

El razonamiento equivocado fue mirar las medias por clase (PortScan tiene PSH=1
siempre) sin mirar la condicional inversa (BENIGN también tiene PSH=1 el 32% de las
veces, y BENIGN es enorme). *«Todos los A son B»* no implica *«todos los B son A»*.

### 4.3 Las razones que sí valen

**Prueba 1 — conversaciones sin acuses de recibo.**
Tomamos los flujos con al menos 4 paquetes en cada sentido y más de 1 ms de duración:
conversaciones TCP reales, no sondas sueltas. Son 101.677.

| Columna | % de esos flujos donde vale 0 |
|---|---|
| `ACK Flag Count` | **80,8 %** |
| `SYN Flag Count` | 98,1 % |
| `FIN Flag Count` | 95,7 % |

Ocho paquetes intercambiados sin un solo ACK no existe en TCP. Es como la
transcripción de una llamada de diez minutos en la que nadie dijo nunca «ajá».

**Prueba 2 — combinaciones imposibles.**
De las 32 combinaciones posibles de 5 banderas, en 2,8 millones de flujos solo
aparecen **10**, y **nunca hay tres banderas activas a la vez**. Cualquier conexión
HTTP completa tiene SYN, ACK, PSH y FIN.

**Prueba 3 — columnas idénticas byte a byte.**
Comparamos todas las columnas buscando duplicados exactos sobre las 2,8M de filas:

```
['Fwd PSH Flags', 'SYN Flag Count']            ← idénticas
['Fwd URG Flags', 'CWE Flag Count']            ← idénticas
['Fwd Header Length', 'Fwd Header Length.1']   ← duplicado conocido
['Total Fwd Packets', 'Subflow Fwd Packets']
['Total Backward Packets', 'Subflow Bwd Packets']
```

`Fwd PSH Flags` mide PSH en sentido de ida. `SYN Flag Count` mide SYN. Son conceptos
distintos y contienen **exactamente los mismos bytes** en los 2,8 millones de filas.
Como si en una planilla las columnas «estatura» y «peso» tuvieran valores idénticos
para todos los empleados. Solo pasa si alguien asignó mal las columnas.

**Prueba 4 — el escaneo sin SYN.**
En 33.150 flujos etiquetados como PortScan hay **0 con SYN=1 y 0 con RST=1**. Un
escaneo SYN contra un puerto cerrado es, por definición, SYN → RST.

### 4.4 La razón decisiva

No es que los datos estén dañados. Son consistentes y reproducibles. El problema es
que **la etiqueta de la columna no corresponde a lo que hay dentro**, y no sabemos a
qué corresponde.

Para tener paridad, nuestro extractor tendría que **reproducir el mismo error** que
una herramienta de 2017 cuyo código no controlamos, y acertar en los trece escenarios
del dataset. No es viable ni defendible.

Es distinto de P1: microsegundos y payload son transformaciones **conocidas y exactas**.
Aquí no hay función que aplicar, porque no sabemos qué mide el origen.

### 4.5 Cuánto cuesta quitarlas

Medido, con Random Forest sobre 480.000 flujos, partición estratificada 70/30:

| Conjunto | F1 |
|---|---|
| 19 características, sin banderas | 0,9598 |
| 24 = 19 + las 5 banderas | 0,9635 |

**+0,0037.** Menos de cuatro milésimas. Pagar irreproducibilidad en vivo por eso no
tiene sentido.

### 4.6 Y esto no perjudica la demo con los pcap de Frank

Al contrario: **evita un fallo que habría ocurrido el día de la defensa.**

Nuestro extractor calcula las banderas *bien*. Ante un escaneo de Frank diría
«hubo 300 SYN». El CSV, para ese mismo escaneo, dice «0 SYN».

Si dejáramos las banderas en el contrato, el modelo aprendería del CSV que
«SYN = 0 significa escaneo», y en la demo recibiría «SYN = 300» y concluiría *«esto
no es un escaneo»*. Fallaría precisamente en el ataque más fácil de detectar.

Al quitarlas, el modelo nunca aprende a mirar esa casilla y tampoco la echa de menos.

Lo que sí perdemos es señal *real*: en el mundo real un escaneo se delata por sus
banderas. Pero no podíamos usarla de todos modos, porque el dataset no nos la daba.
Perdimos algo que nunca tuvimos.

### 4.7 Qué entra en su lugar

Cinco características de familias cuya conversión ya sabemos hacer:

| Entra | Qué mide | Qué recupera |
|---|---|---|
| `flow_iat_max` | el silencio más largo dentro del flujo | **La firma del low-and-slow.** Un slowloris manda cosas muy espaciadas para no llamar la atención; esa pausa es su huella. |
| `flow_iat_min` | el hueco más corto | El extremo opuesto: la ráfaga de una inundación. |
| `fwd_pkt_len_min` | paquete de ida más pequeño | Cierra el cuarteto min/media/desv/máx. Un escaneo da 0. |
| `bwd_pkt_len_min` | paquete de vuelta más pequeño | Ídem en el sentido de vuelta. |
| `fwd_act_data_pkts` | paquetes de ida que llevan datos reales | «Este flujo no transporta nada»: recupera por otra vía parte de lo que daban las banderas. |

Resultado medido: la detección de **DoS Slowhttptest sube de 0,869 a 0,938** y
**slowloris de 0,986 a 0,993**. Son justamente los ataques lentos, es decir el
escenario con el que vamos a argumentar que el ML le gana a la regla fija.

---

## 5. P3 — La trampa: el modelo detectaba el sistema operativo

Este hallazgo no estaba en el radar de nadie y es el más importante del proyecto.

### 5.1 Qué encontramos

Al entrenar con las 76 características comunes, el F1 saltó a **0,9948** y
`Init_Win_bytes_forward` resultó ser la característica más importante de todas.

Esa columna guarda la **ventana TCP inicial**: cuando una máquina abre una conexión,
anuncia cuánta memoria reserva para recibir. Cada sistema operativo usa un valor
distinto por defecto. Es como el acento: no dice nada de lo que la persona *dice*,
pero delata de dónde viene.

Mediana por etiqueta:

| Etiqueta | `Init_Win_bytes_forward` | valores distintos |
|---|---|---|
| BENIGN | 119 | 5.776 |
| PortScan | **29200** | 6 |
| SSH-Patator | **29200** | 4 |
| DoS slowloris | **29200** | 3 |
| Web Attack (×3) | **29200** | 5 |

29200 es la ventana inicial por defecto de Linux. CICIDS2017 se grabó con **una sola
máquina atacante**, una Kali Linux, contra víctimas Windows. Así que la regla que
aprendió el modelo fue:

> ventana = 29200 → viene de la Kali → **es ataque**

El modelo no aprendió a reconocer ataques. Aprendió a reconocer **una computadora
concreta**. Como un guardia que en vez de detectar ladrones memorizó una cara.

### 5.2 Por qué en nuestro laboratorio sería un desastre

**Nuestras dos VM son Fedora 44.** Atacante y víctima, mismo sistema, misma ventana
inicial. Consecuencia doble:

1. La característica **no separa nada**: atacante y víctima se ven idénticos.
2. Peor: el modelo aprendió «ventana de Linux = ataque». Frank navega desde la VM
   atacante, hace SSH normal, transfiere un archivo — y **todo eso sale con ventana
   de Linux**. El modelo lo marca como ataque y el SOAR empieza a bloquear tráfico
   legítimo.

Habríamos presentado un F1 de 0,99 y un sistema que bloquea todo en la demo.

Esto tiene nombre en el documento maestro: **desfase de dominio** (sección 6.4). Es
el riesgo principal declarado del proyecto, y aquí lo cazamos en el sitio exacto donde
se escondía.

### 5.3 La regla general que sale de aquí

> Rechazamos cualquier característica que **identifique el entorno** en lugar del
> comportamiento, aunque suba el F1.

Sirve también para descartar IP, puertos y timestamp (que ya estaban excluidos por
fuga de datos): son casos particulares del mismo principio.

---

## 6. P4 — Basura, redundancia e infinitos

De las 78 columnas:

**8 son constantes en cero** (varianza cero, cero información):
`Bwd PSH Flags`, `Bwd URG Flags` y las 6 de bulk (`Fwd/Bwd Avg Bytes/Packets/Rate per Bulk`).

**5 son duplicados o derivados exactos** de otra columna:
- `Subflow Fwd Packets` = `Total Fwd Packets`
- `Subflow Bwd Packets` = `Total Backward Packets`
- `Subflow Fwd Bytes` = `Total Length of Fwd Packets`
- `Avg Fwd Segment Size` = `Fwd Packet Length Mean`
- `Avg Bwd Segment Size` = `Bwd Packet Length Mean`

Incluirlas es gastar plazas del contrato dos veces por el mismo dato.

**2 tienen NaN e infinitos**, por división entre duración cero:
- `Flow Bytes/s`: 1.358 NaN y 1.509 infinitos
- `Flow Packets/s`: 2.867 infinitos

No se descartan (son útiles) pero **el contrato define su tratamiento**: infinito y
NaN se convierten en 0. Esto tiene que estar escrito, no improvisado en el
preprocesado, o entrenamiento y demo harán cosas distintas.

**2.886 filas tienen algún valor negativo finito.** Corruptas. Se eliminan en A3.

> **Corregido tras A3.** Esta sección decía «22 filas tienen `Flow Duration`
> negativa». Las dos mitades de la frase estaban mal: sobre los 8 CSV completos son
> **115** las de `Flow Duration` —el 22 salió de una ejecución con `--sample`— y el
> total real es **2.886**, con el grueso en `Flow IAT Min`, columna que esta auditoría
> nunca llegó a probar. Ver §11.3 y `contract/A3_preprocessing_note.md` §2.1.

---

## 7. Por qué exactamente 24

Esta es la pregunta que hay que saber responder, porque el número venía de una
propuesta previa y no de un análisis.

### 7.1 El embudo: de 78 a 51

| Paso | Se quitan | Quedan |
|---|---|---|
| Columnas del CSV (sin `Label`) | — | 78 |
| Identidad (`Destination Port`) — fuga de datos | 1 | 77 |
| `Fwd Header Length.1` — duplicado del archivo | 1 | 76 |
| Constantes | 8 | 68 |
| Duplicados y derivados exactos | 5 | 63 |
| Banderas irreproducibles (§4) | 10 | 53 |
| Huella de entorno (§5) | 2 | **51** |

Hasta aquí no hemos elegido nada: hemos **eliminado lo que no puede usarse**. Las 51
restantes son todas legítimas.

### 7.2 La medición que justifica el 24

Ordenamos las 51 por importancia — calculada **solo sobre el conjunto de
entrenamiento**, sin tocar el de prueba — y medimos el F1 según cuántas se usan:

| Nº de características | F1 | PR-AUC | Ganancia sobre el paso anterior |
|---|---|---|---|
| 5 | 0,9387 | 0,9653 | — |
| 10 | 0,9451 | 0,9690 | +0,0064 |
| 20 | 0,9629 | 0,9895 | +0,0178 |
| **24** | **0,9685** | **0,9938** | **+0,0056** |
| 30 | 0,9685 | 0,9939 | +0,0000 |
| 51 (todas) | 0,9689 | 0,9944 | +0,0004 |

**El rendimiento satura en 24.** Usar las 51 disponibles en lugar de 24 mejora el F1
en cuatro diezmilésimas.

### 7.3 Las cuatro razones para no pasar de ahí

1. **Rendimiento saturado.** Medido arriba. Más características no aportan.
2. **Coste de validación.** La Tarea A2 exige comprobar, número por número, que cada
   característica vale lo mismo por CSV y por extractor. Ese trabajo crece linealmente.
   Validar 51 no cabe en el tiempo disponible; validar 24, sí. Y una característica no
   validada es peor que no tenerla.
3. **Superficie de riesgo.** Cada característica extra es otra oportunidad de que se
   cuele algo como `Init_Win_bytes`: algo que funciona en el CSV y se derrumba en el
   laboratorio. Menos características es menos superficie donde esconder ese fallo.
4. **Latencia.** El sistema evalúa flujos completos y además ventanas parciales cada
   pocos segundos, en vivo. Calcular 24 números es más barato que calcular 51, y el
   criterio de aceptación incluye la latencia de contención p95.

### 7.4 Cómo decirlo en la defensa

> «Partimos de 78 columnas. Eliminamos 27 por criterios objetivos: identidad,
> varianza cero, duplicación exacta, imposibilidad de reproducirlas en vivo y
> dependencia del entorno. Quedaron 51 utilizables. Medimos la curva de rendimiento
> frente al número de características y encontramos que satura en 24: usar las 51
> mejora el F1 en 0,0004. Fijamos 24 porque es donde el rendimiento se estabiliza y
> porque es el número que podemos validar en paridad una por una, que es la condición
> de salida de la fase 0.»

Y si preguntan por qué no 20 o 30: **porque 24 estaba comprometido con Frank desde el
día 1**, y romper el contrato sin ganancia medible es exactamente lo que el proyecto
quiere evitar. La estabilidad de la interfaz vale más que 0,0004 de F1.

---

## 8. Las 24 y sus cinco grupos

La especificación exacta está en `contract_characteristics.md`. Aquí, el porqué de
cada grupo:

| Grupo | Nº | Qué detecta |
|---|---|---|
| Duración y volumen | 5 | Distingue el escaneo (flujos minúsculos) de la inundación (muchísimos paquetes). |
| Tamaños de paquete de ida | 4 | La fuerza bruta produce tamaños muy regulares; el tráfico normal, variados. |
| Tamaños de paquete de vuelta | 4 | La respuesta del servidor delata si la conversación es real o solo sondeo. |
| Tamaños del flujo completo | 2 | Resumen global de la conversación. |
| Ritmo temporal | 6 | **Donde se delata el low-and-slow**: el espaciado artificial. |
| Tasas y datos útiles | 3 | Velocidad de la conversación y si transporta algo real. |

Nota sobre la simetría: el documento maestro proponía `down_up_ratio`. Se descartó
porque resultó la menos importante de las 24 (0,0039) y además exigía una tercera
regla de conversión (el CSV usa división entera, nuestro extractor devuelve float).
La simetría sigue estando: al tener volúmenes de ida y de vuelta por separado, el
modelo puede construir la relación por sí mismo si le sirve.

---

## 9. Rendimiento esperado y el problema abierto

Random Forest, 480.000 flujos, partición estratificada 70/30, sin ajuste de
hiperparámetros:

| Métrica | Valor | Criterio del proyecto |
|---|---|---|
| F1 clase ataque | **0,960** | ≥ 0,90 ✅ |
| Precisión | 0,938 | — |
| Recall | 0,983 | — |
| PR-AUC | 0,993 | — |

Detección por tipo de ataque:

| Ataque | Recall | Escenario de la demo |
|---|---|---|
| PortScan | 0,999 | ✅ escaneo rápido y lento |
| DDoS | 0,998 | ✅ inundación |
| DoS Hulk | 0,975 | — |
| DoS GoldenEye | 0,946 | — |
| DoS slowloris | 0,993 | ✅ ataque lento |
| DoS Slowhttptest | 0,938 | — |
| FTP-Patator | 0,993 | — |
| **SSH-Patator** | **0,500** | ⚠️ **fuerza bruta SSH** |

### El problema de SSH-Patator

La fuerza bruta SSH se detecta al 50%, y es **uno de los cuatro ataques prometidos**.

La causa es conocida: en CICIDS2017, SSH-Patator solo se separa bien del tráfico
benigno usando la ventana TCP inicial — o sea, la característica que descartamos por
ser huella de entorno. Sin ella, sus flujos se parecen mucho a sesiones SSH normales.

Tres respuestas legítimas, y proponemos usar las tres:

1. **El SOAR lo compensa.** Un `hydra` genera cientos de flujos. Detectar el 50% de
   300 flujos produce ~150 alertas sobre la misma IP, y la deduplicación de PB-01 las
   agrupa en **un caso** que dispara la contención igual. *La tasa de detección por
   flujo no es la tasa de detección del ataque.* Esto hay que decirlo en la defensa
   antes de que lo pregunten.
2. **Bajar el umbral.** Ese 50% es a umbral 0,5. La Tarea A6 existe para mover esa
   perilla, y este es el argumento concreto para bajarla.
3. **Recalibrar con tráfico propio (Tarea A7).** Con las capturas de `hydra` que nos
   pase Frank, el modelo aprende el patrón real de nuestro laboratorio en lugar del
   artefacto de 2017.

**Frank: esto te afecta.** Si el umbral baja de 0,70, los cortes de severidad de
`config.py` (`SEV_MEDIUM`, `SEV_HIGH`) hay que revisarlos juntos en la fase 4.

---

## 10. Lo que queda pendiente

| Pendiente | De quién | Cuándo |
|---|---|---|
| **Frank revisa y acepta el contrato** | Frank | ahora — es el criterio de «hecho» de A1 |
| Mapeo de etiquetas: qué familias son ATTACK=1 y cuáles se excluyen | Sebastián | antes de A3 |
| Implementar `extract_features()` con las dos conversiones | Sebastián | A2 |
| Validar paridad número por número sobre un pcap real de Frank | Sebastián | A2 |
| Investigar los IAT en cero para flujos de un solo intervalo | Sebastián | A2 |
| Umbral definitivo y su efecto en la severidad | ambos | A6 / fase 4 |

### Sobre el mapeo de etiquetas

Propuesta a decidir: `BENIGN → 0`; `PortScan, DDoS, DoS Hulk, DoS GoldenEye,
DoS slowloris, DoS Slowhttptest, SSH-Patator, FTP-Patator → 1`; y **excluir**
`Infiltration` (9 casos en la muestra), `Heartbleed`, `Bot` y los `Web Attack`,
porque no son escenarios de la demo y con esos volúmenes solo aportan ruido.

La alternativa es entrenar solo con los cuatro de la demo: modelo más afilado para lo
que se va a demostrar, pero peor generalización. Ninguna es obviamente mejor.

### Sobre el orden de A1 y A2

El documento de Frank propone no cerrar la selección hasta comprobar que todo se
reproduce en vivo. De acuerdo en el espíritu, pero en la práctica bloquea: sin
contrato congelado no se puede escribir el extractor, y sin extractor no hay nada que
verificar.

La solución es **versionar**. El contrato se congela ahora como `v1.0`. Si A2 detecta
que alguna característica no alcanza la paridad, sale `v1.1` y se avisa a Frank
explícitamente. Es la única forma de romper la circularidad.

---

## 11. Errores nuestros registrados

Para el registro de copiloto y por honestidad metodológica, tres afirmaciones que se
hicieron durante el análisis y resultaron falsas:

1. **«`RST Flag Count` es constante en cero.»** Falso. Hay 686 flujos con RST=1
   (0,024%) en el dataset completo. La afirmación venía de mirar 200.000 filas de un
   solo archivo y generalizar.
2. **«Las banderas separan PortScan perfectamente, es fuga de datos.»** Falso, medido:
   F1 = 0,000 usando solo las banderas para ese problema. El error fue mirar medias
   condicionales por clase sin comprobar la condicional inversa.

3. **«22 filas tienen `Flow Duration` negativa.»** Falso por partida doble, detectado
   en A3. Son **115**: el 22 se midió con `audit_dataset.py --sample` (60.000 filas
   por archivo, ~17% del dataset), y está reproducido — la misma consulta sobre esa
   muestra devuelve exactamente 22. Y, más importante, el total de filas corruptas es
   **2.886**: la auditoría solo probó negativos en `Flow Duration`, la columna que
   alguien sospechaba, y las otras **2.771** están sobre todo en `Flow IAT Min`, que
   nadie miró. Lo que las destapó fue derivar la regla del contrato en lugar de la
   sospecha: `validate()` ya declaraba las 24 posiciones como no negativas, así que
   A3 comprobó las 24.

Los tres se detectaron al auditar el dataset completo en vez de una muestra parcial.
La lección práctica, en dos partes: **auditar sobre los 8 archivos completos, no sobre
`nrows=200000` de uno solo** —por eso `audit_dataset.py` corre sobre todo por
defecto— y, la que añade el tercero, **comprobar la propiedad allí donde el contrato
la declara, no solo donde uno espera encontrarla rota.** Una muestra da la cifra mal;
mirar una sola columna no da la cifra en absoluto.
