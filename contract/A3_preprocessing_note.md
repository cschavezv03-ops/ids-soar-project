# Nota de preprocesamiento A3 — Del CSV crudo a la partición

**Tarea:** A3, convertir los 8 CSV de CICIDS2017 en una partición
entrenamiento/prueba estratificada y reproducible.
**Contrato:** v1.0, sin cambios. A3 **añade** código; no enmienda el contrato.
**Alcance:** cargar, etiquetar, limpiar y partir. Aquí no se entrena, no se
escala, no se remuestrea y no se mide nada.
**Dataset de trabajo resultante:** 1.990.162 flujos, 83,33 % BENIGN /
16,67 % ATTACK, partidos en 1.592.129 / 398.033. Se regenera con
`python src/intelligence/preprocess.py --drop-duplicates` (§4).

---

## 1. Qué reglas del contrato se aplican de este lado, y por qué

La sección 5 de `contract_characteristics.md` define cuatro reglas. **Solo dos
de ellas tocan el CSV.** Cuál se aplica dónde no es una comodidad de
implementación: se deduce de la dirección de la conversión.

> **El extractor se adapta al CSV, nunca al revés.** El CSV es el espacio de
> referencia: es el que el modelo aprenderá, y el que el sistema en vivo tiene
> que reproducir. Una regla que exista para acercar el extractor al CSV no
> tiene nada que hacer del lado del CSV — aplicarla aquí sería alejar la
> referencia de sí misma.

| Regla | ¿Aplica al CSV? | Motivo |
|---|---|---|
| **R1** — tiempo en microsegundos | **No** | El CSV ya está en microsegundos. Es la unidad de destino, no la de origen. El que convierte es el extractor, que mide en segundos. |
| **R2** — longitud = payload con relleno Ethernet | **No** | El CSV **define** la medición. Además la conversión inversa no existe: ninguna operación reconstruye cabeceras y relleno de trama a partir del payload. El arreglo vive necesariamente en la *medición* del extractor. |
| **R3** — no finitos → 0.0 | **Sí** | Única regla **bidireccional**. Los dos caminos ejecutan la misma regla desde la misma fuente: el CSV llama a `contract.sanitize_frame()`, el extractor en vivo llama a `contract.sanitize()`. |
| **R4** — filas corruptas | **Sí, y solo aquí** | Sin contrapartida en vivo por diseño: offline se puede descartar una fila; en vivo llega un flujo y hay que clasificarlo. |

### R3 implementada dos veces sin poder divergir

`sanitize_frame()` es la versión vectorizada de `sanitize()`. Existe únicamente
porque 2,8 millones de filas no se recorren con un bucle de Python. Que ambas
hagan exactamente lo mismo es lo que impide que entrenamiento e inferencia se
separen en silencio, y **está fijado por prueba**, no por convención:
`tests/test_preprocess.py` ejecuta las dos sobre el mismo marco de datos —
casos límite construidos a mano y 3.000 filas aleatorias sembradas de NaN, +inf
y −inf — y exige salida idéntica.

La trampa concreta que evita: `np.nan_to_num` convierte `+inf` en ~1,8×10³⁰⁸ por
defecto, **no en 0**. El código usa `replace([inf, -inf], MISSING_VALUE).fillna(MISSING_VALUE)` y hay
una prueba dedicada a ese valor.

### R4 se comprueba en las 24 posiciones, no en una columna

`contract.validate()` declara las 24 posiciones como magnitudes no negativas
(`NON_NEGATIVE_IDX` es el rango completo). La regla sigue al contrato, no a la
columna en la que A1 encontró ejemplos.

Solo se descartan **negativos finitos**. El `−inf` es asunto de R3, no de R4:
descartarlo eliminaría flujos legítimos de duración cero, que es justo lo que
produce un escaneo de puertos.

**El orden importa y es R4 → R3.** Al revés, `sanitize` convertiría el `−inf` en
0.0 y una fila corrupta pasaría a parecer impecable y entraría al entrenamiento.
Hay una prueba que fija ese orden.

---

## 2. Lo que las cifras dicen, y dónde contradicen a A1

Evidencia completa: `scripts/scripts_output/preprocess_report.txt`.

### 2.1 Filas corruptas: 2.886, no 22

A1 documentó «22 filas con `Flow Duration` negativa». La cifra real sobre el
dataset completo es **115**, y el total de filas con algún negativo finito es
**2.886**. Son dos errores distintos y ambos están explicados:

| | A1 | A3 | Causa |
|---|---|---|---|
| `Flow Duration` negativa | 22 | **115** | El 22 se midió con `audit_dataset.py --sample` (60.000 filas por archivo, ~17 % del dataset). Verificado: la misma consulta sobre la muestra devuelve exactamente 22. |
| Total de filas corruptas | 22 | **2.886** | La auditoría solo probó negativos en `Flow Duration`. El grueso está en `Flow IAT Min`, que nadie había mirado. |

Desglose por columna (una fila puede ofender en varias):

| Columna | Filas |
|---|---|
| `flow_iat_min` | 2.886 |
| `flow_duration` | 115 |
| `flow_iat_mean` | 115 |
| `flow_iat_max` | 115 |
| `flow_pkts_s` | 115 |
| `flow_byts_s` | 85 |

Las 115 de `flow_duration` son un subconjunto de las 2.886: una duración
negativa arrastra a los estadísticos que se derivan de ella.

Reparto de la pérdida por familia, que es lo que decide si 2.886 filas importan:

| Familia | Filas perdidas |
|---|---|
| BENIGN | −2.697 |
| DoS Hulk | −159 |
| DDoS | −19 |
| DoS GoldenEye | −5 |
| FTP-Patator | −4 |
| SSH-Patator | −2 |
| DoS slowloris | −0 |
| DoS Slowhttptest | −0 |

**Ninguna familia pequeña se ve afectada de forma apreciable.** El 93 % de las
bajas son BENIGN, la clase que sobra, y las dos familias más frágiles del
contrato —`DoS slowloris` y `DoS Slowhttptest`— no pierden ni una fila. Por eso
2.886 sobre 2,8 millones (0,10 %) no cambia ninguna decisión: solo cambia una
cifra publicada.

**Corregido en los documentos aguas arriba:** `A1_analysis_and_decisions.md` §6
y §11.3, y la regla R4 de `contract_characteristics.md`. La corrección **no
modifica el contrato ni su versión**: no cambian el número de características,
ni su orden, ni sus unidades, ni las posiciones a las que R4 se aplica.

### 2.2 Valores no finitos (R3): 5.712 celdas

| Columna | NaN | inf |
|---|---|---|
| `flow_pkts_s` | 0 | 2.856 |
| `flow_byts_s` | 1.357 | 1.499 |

Concuerda con A1 (1.358 NaN y 1.509 inf en `Flow Bytes/s`; 2.867 inf en
`Flow Packets/s`) una vez descontadas las filas que los pasos previos ya
eliminaron: 10 inf en cada columna se van con las familias excluidas y 1 NaN y
1 inf más se van con R4. Aquí A1 sí había medido sobre el dataset completo.

### 2.3 Etiquetas

15 valores distintos. Se conservan BENIGN y 8 familias de ataque; se descartan
**4.193 filas** (Bot 1.966, las 3 variantes de Web Attack 2.180, Infiltration 36,
Heartbleed 11). Descartar no es reetiquetar: esas filas **no** pasan a benignas,
porque enseñar al modelo que un flujo de botnet es tráfico normal es peor que no
enseñarle nada sobre él. `label_to_target()` lanza excepción ante una etiqueta
desconocida y el pipeline **no la captura**: un valor por defecto silencioso
envenenaría el conjunto de entrenamiento sin producir ningún error.

---

## 3. Proporciones finales documentadas

Tres filtros, en este orden: excluir familias (−4.193), R4 (−2.886), y
**eliminar duplicados exactos (−833.502, decisión D3, §5.1)**.

| Paso | Flujos restantes |
|---|---|
| Cargados de los 8 CSV | 2.830.743 |
| Tras excluir familias (§2.3) | 2.826.550 |
| Tras R4 (§2.1) | 2.823.664 |
| **Tras eliminar duplicados** | **1.990.162** |

Este último es **el dataset de trabajo de A4 en adelante.**

| Clase | Flujos | % |
|---|---|---|
| BENIGN (0) | 1.658.454 | **83,33 %** |
| ATTACK (1) | 331.708 | **16,67 %** |

| Familia | Flujos | % | Antes de deduplicar |
|---|---|---|---|
| BENIGN | 1.658.454 | 83,33 % | 80,41 % |
| DoS Hulk | 171.822 | 8,63 % | 8,18 % |
| DDoS | 127.996 | 6,43 % | 4,53 % |
| DoS GoldenEye | 10.276 | 0,52 % | 0,36 % |
| FTP-Patator | 5.929 | 0,30 % | 0,28 % |
| DoS slowloris | 5.382 | 0,27 % | 0,21 % |
| DoS Slowhttptest | 5.227 | 0,26 % | 0,19 % |
| SSH-Patator | 3.151 | 0,16 % | 0,21 % |
| **PortScan** | **1.925** | **0,10 %** | **5,63 %** |

El desequilibrio global **empeora** al deduplicar: de 80/20 a 83/17. Era
previsible —los ataques repiten más que el tráfico benigno— y es el precio
aceptado en §5.1.

### La partición

`test_size=0.2`, `random_state=42`, **estratificada por la cadena de etiqueta
original**, no por el objetivo binario. Estratificar por el binario solo
garantizaría la proporción benigno/ataque global: podría llevarse casi todo
`DoS Slowhttptest` al entrenamiento y dejar el conjunto de prueba incapaz de
decir nada sobre esa familia. A5 necesita medir recall **por familia**.

| | Filas | BENIGN | ATTACK |
|---|---|---|---|
| Entrenamiento | 1.592.129 | 83,33 % | 16,67 % |
| Prueba | 398.033 | 83,33 % | 16,67 % |

Las nueve familias conservan su proporción en ambas mitades hasta la segunda
cifra decimal (tabla completa en el reporte, sección 8). Está impreso para
poder comprobarlo a ojo, no afirmado.

La familia más pequeña, PortScan, aporta **385 flujos al conjunto de prueba**.
Sigue siendo suficiente para que A5 mida su recall con un intervalo de
confianza razonable, pero es la cifra que hay que vigilar: era 31.786.

### Desequilibrio: no se toca aquí

Tratamiento decidido: `class_weight="balanced"` **dentro del Pipeline de
sklearn en A4**. Es un hiperparámetro del modelo, no una propiedad de los datos,
así que A3 no modifica `X_train` en absoluto. **No se remuestrea**: SMOTE o
submuestreo cambiarían lo que el modelo ve sin cambiar lo que los datos
significan, y además invalidarían las cifras de esta sección.

Nótese que eliminar duplicados **no es remuestrear**. Un duplicado exacto no
aporta información nueva y puede caer a ambos lados de la partición; una fila
sintética o una fila descartada al azar sí alteran la distribución a propósito.
Son operaciones distintas y solo la primera se aplica.

---

## 4. Cómo se regenera todo

Desde la raíz del repositorio, con el entorno virtual activo:

```bash
# El dataset de trabajo y el reporte de evidencia. La bandera NO es opcional:
# es la decisión D3 (§5.1), y sin ella se obtiene el dataset con duplicados.
python src/intelligence/preprocess.py --drop-duplicates

# Las pruebas: 58 previas + 19 de A3
pytest -q
```

Sin la bandera, `preprocess.py` produce el dataset **con** duplicados. Se
mantiene ejecutable a propósito: es lo que permite reproducir las cifras de la
§5.1 y comparar los dos entrenamientos si A5 lo pide.

Salidas:

| Ruta | Qué es | ¿En git? |
|---|---|---|
| `scripts/scripts_output/preprocess_report.txt` | La evidencia | **Sí** |
| `data/processed/train.parquet` | 1.592.129 filas: 24 features + `target` + `label` | No |
| `data/processed/test.parquet` | 398.033 filas, ídem | No |

`data/` está en `.gitignore`. **El artefacto reproducible es el script más esta
nota, no los bytes en disco.** El formato es parquet porque `pyarrow` ya
figuraba en `requirements.txt`: A3 no añadió ninguna dependencia. Se escriben
dos archivos y no seis para que una fila no pueda separarse de su propia
etiqueta por un índice desalineado; `preprocess.load_processed()` los devuelve
como los seis objetos (`X_train, X_test, y_train, y_test, label_train,
label_test`).

Coste: ~12 s y ningún acceso de escritura a `data/raw/`.

---

## 5. Decisiones tomadas y lo que sigue abierto

### 5.1 D3 — Duplicados exactos: se eliminan. DECIDIDA

**833.502 filas duplicadas (29,52 %)** sobre las 24 features más la etiqueta
original. El reparto no era uniforme, y es lo que hacía que la decisión no
fuera obvia:

| Familia | Total | Duplicadas | % |
|---|---|---|---|
| PortScan | 158.930 | 157.005 | **98,8 %** |
| SSH-Patator | 5.895 | 2.744 | 46,5 % |
| BENIGN | 2.270.400 | 611.946 | 27,0 % |
| DoS Hulk | 230.914 | 59.092 | 25,6 % |
| FTP-Patator | 7.934 | 2.005 | 25,3 % |
| DoS slowloris | 5.796 | 414 | 7,1 % |
| DoS Slowhttptest | 5.499 | 272 | 4,9 % |
| DoS GoldenEye | 10.288 | 12 | 0,1 % |
| DDoS | 128.008 | 12 | 0,0 % |

**Decisión: se eliminan.** El pipeline se ejecuta con `--drop-duplicates` y su
salida es el dataset de trabajo de A4 en adelante.

**Motivo: ninguna fila puede aparecer a la vez en entrenamiento y en prueba.**
Una fila duplicada tiene un vector idéntico y una etiqueta idéntica; si una
copia cae en entrenamiento y otra en prueba, el modelo la ha visto durante el
entrenamiento y el conjunto de prueba deja de medir generalización para medir
memorización. Con un 29,52 % de duplicados globales, **el recall de A5 no sería
interpretable**, y con un 98,8 % en PortScan lo que se estaría midiendo sobre
esa familia es casi exclusivamente memorización. Una métrica que no se puede
interpretar no vale más que ninguna métrica.

**Coste aceptado, explícitamente:**

> **PortScan cae de 158.930 a 1.925 flujos**, del 5,63 % al 0,10 % del dataset:
> de tercera familia a la más pequeña de las nueve. En el conjunto de prueba
> quedan **385 flujos** de escaneo, frente a 31.786 antes.

Es un coste real y hay que saber defenderlo, no minimizarlo. Se acepta por dos
razones:

1. **Los 157.005 duplicados eran una sola forma repetida.** Un escaneo emite
   miles de flujos con el mismo vector: misma duración, mismo tamaño, mismos
   cero bytes de payload. 1.925 flujos distintos siguen conteniendo **todas**
   las formas distintas que el escaneo produce en el dataset; lo que se pierde
   es la frecuencia, no la variedad. El modelo no puede aprender de la
   repetición nada que no aprenda de la primera copia.
2. **El argumento mitigador ya está escrito en A1 §9.** El SOAR deduplica: la
   detección de PB-01 agrupa cientos de flujos de una misma IP en **un caso**,
   que dispara la contención una vez. *La tasa de detección por flujo no es la
   tasa de detección del ataque.* Un escaneo real genera cientos de flujos y
   basta con acertar en algunos para que el caso se abra y la contención actúe.
   A1 usó ese argumento para SSH-Patator al 50 % de recall; aplica igual aquí, y
   por el mismo motivo estructural.

**Riesgo residual reconocido:** si en A5 el recall de PortScan cae de forma
apreciable, la primera hipótesis a comprobar es esta decisión, no el modelo. La
bandera sigue existiendo y el dataset con duplicados se regenera en 12 s, así
que la comparación es barata.

### 5.2 Nota para A6 — la calibración cambia de mezcla

Eliminar duplicados **no cambia qué patrones existen, pero sí con qué frecuencia
aparecen**. Un Random Forest estima probabilidades a partir de la proporción de
clases en las hojas, de modo que las probabilidades que `predict()` devuelva
estarán calibradas sobre una mezcla distinta de la que produce una captura
cruda: en el tráfico real, un escaneo sí emite miles de flujos idénticos, y en
el dataset de entrenamiento ya no.

En la práctica esto significa que **el 0,5 por defecto pierde el poco
significado que tenía**, y que la probabilidad que el panel muestre no debe
leerse como «frecuencia esperada en la red».

**No es un problema, es un registro.** El umbral se recalibra de todas formas:
A6 lo elige por curva precisión/recall sobre el conjunto de prueba, y A7 lo
reajusta contra tráfico del laboratorio, cuya mezcla no se parece ni a una ni a
otra. Simplemente conviene que en A6 nadie se sorprenda de que las
probabilidades salgan desplazadas, ni intente corregirlo tocando el
preprocesamiento.

### 5.3 El umbral de decisión — A6/A7

`predict()` devuelve una probabilidad; el sistema necesita un corte. Con
83/17 de desequilibrio y `class_weight="balanced"`, el 0,5 por defecto no tiene
por qué ser el punto de operación correcto: la contención SOAR actúa sobre los
positivos, así que el coste de un falso positivo es un bloqueo indebido, no una
casilla mal marcada en una matriz.

Dos cosas quedan pendientes y **no se resuelven con este dataset**:

1. **A6** — elegir el umbral sobre el conjunto de prueba de CICIDS2017, por
   curva precisión/recall, no por accuracy. Con el desplazamiento de §5.2 en
   mente.
2. **A7** — recalibrarlo contra tráfico del laboratorio. La nota A2 ya avisó de
   que las capturas benignas de Frank son flujos únicos y largos (un SSH = 1
   flujo = 1 ejemplo), no cientos: qué capturas hacen falta depende de cómo se
   calibre, y es decisión de A7.

También sigue abierto, de A1 §9: si el umbral baja de 0,70, los cortes de
severidad de `config.py` (`SEV_MEDIUM`, `SEV_HIGH`) hay que revisarlos con
Frank en la fase 4.

El riesgo de fondo sigue siendo el mismo que identificó A1: **desfase de
dominio**. Las proporciones de la sección 3 son las de CICIDS2017 en 2017,
deduplicadas, no las de la red del laboratorio.

---

## 6. Cobertura de pruebas

19 pruebas nuevas en `tests/test_preprocess.py`, todas sobre marcos sintéticos
de unas pocas filas. **Ninguna carga `data/raw/`**: el archivo entero termina en
0,6 s y se puede ejecutar en cada guardado. El dataset es evidencia, no un
fixture.

| Grupo | Qué fija |
|---|---|
| Equivalencia R3 (5) | `sanitize_frame` == `sanitize` fila a fila, sobre casos límite y sobre 3.000 filas aleatorias; la trampa de `np.nan_to_num`; el casteo a float; no mutar la entrada |
| R4 (5) | Descarta un negativo finito **fuera** de `Flow Duration`; descarta `Flow Duration` negativa; **no** descarta `−inf`, NaN ni `+inf`; el orden R4 → R3 deja el `−inf` en 0.0 |
| Etiquetas (3) | Las familias excluidas se eliminan, no se reetiquetan como benignas; Web Attack se detecta por prefijo ASCII; una etiqueta desconocida lanza excepción |
| Partición (4) | Estratificación por familia dentro de tolerancia en ambas mitades; tamaños; reproducibilidad con la misma semilla; cada fila sigue alineada con su etiqueta |
| Duplicados (2) | El conteo no altera el marco de datos —eliminar es cosa de la bandera, no de la medición—; mismas features con etiqueta distinta no son duplicado |

**Total del repositorio: 77 pruebas en verde** (26 contrato + 19 parches + 13
extractor + 19 preprocesamiento).
