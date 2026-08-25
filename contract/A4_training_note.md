# Nota de entrenamiento A4 — Los tres clasificadores y un cambio de enfoque

**Tarea:** A4, entrenar los tres clasificadores y dejar sus predicciones sobre el
conjunto de prueba listas para la comparación.
**Contrato:** v1.0, sin cambios.
**Estado:** cerrada. El Random Forest supera el criterio del proyecto (F1 ≥ 0,90)
con **F1 = 0,9920** sobre la clase ataque.
**Evidencia completa:** `scripts/scripts_output/train_report.txt`.

---

## 1. Por qué existe este documento

A4 no era una tarea de hallazgos. Era ejecutar tres entrenamientos previstos. Pero
al medir la línea base apareció que **el proyecto llevaba desde A1 argumentando su
tesis con un ejemplo que los datos no sostienen**, y eso hay que dejarlo escrito
antes de que alguien lo descubra leyendo la tabla.

Este documento registra dos cosas que el plan original no contemplaba:

1. **La regla fija estaba apuntada al revés** (§3). Tal y como está redactada en el
   documento maestro, no distingue nada: puntúa exactamente lo mismo que un
   clasificador que marca todo como ataque.
2. **Un defecto de despliegue** que impedía cargar uno de los tres modelos desde
   cualquier proceso distinto del que lo entrenó (§5).

Lo que no repite: el contrato de 24 características (`contract_characteristics.md`),
la validación de paridad (`A2_validation_note.md`) ni el preprocesamiento y la
decisión D3 sobre duplicados (`A3_preprocessing_note.md`).

---

## 2. Resultado del entrenamiento

Sobre la partición que dejó A3: 1.592.129 filas de entrenamiento y 398.033 de
prueba, 83,33 % BENIGN / 16,67 % ATTACK en ambas mitades.

| Modelo | CV F1 (media ± σ) | Precisión | Recall | **F1 en test** |
|---|---|---|---|---|
| **Random Forest** | 0,9913 ± 0,0008 | 0,9888 | 0,9952 | **0,9920** |
| Regresión logística | 0,8204 ± 0,0020 | 0,7395 | 0,9080 | 0,8151 |
| Regla fija | 0,6063 ± 0,0049 | 0,7285 | 0,5122 | 0,6015 |

Todas las cifras se toman al umbral 0,5 por defecto. **Eso es un marcador de
posición, no una decisión:** el punto de operación lo fija A6.

Dos comprobaciones que un lector externo va a querer:

- **Sobreajuste.** Random Forest: F1 en entrenamiento 0,9965, en prueba 0,9920.
  Brecha **0,0045**. Un bosque sin límite de profundidad ajusta el entrenamiento
  casi a la perfección por construcción, de modo que la brecha se espera; lo que
  importa es que la cifra de prueba se sostiene.
- **Estabilidad.** La desviación típica entre los 5 pliegues de validación cruzada
  es 0,0008. El resultado no es un artefacto de una partición afortunada.

La validación cruzada se hizo sobre una submuestra estratificada de 300.000 filas
(18,8 % del entrenamiento). Es un compromiso de tiempo deliberado y se declara: la
pregunta que responde la validación cruzada es si la puntuación es estable entre
particiones, y 300.000 filas la responden igual de bien. **Los modelos finales se
ajustaron sobre el conjunto de entrenamiento completo.**

---

## 3. El cambio de enfoque: la regla fija estaba apuntada al revés

### 3.1 Qué decía el plan

El documento maestro describe la línea base como **«más de N conexiones en 10
segundos»**. Esa regla no es implementable en este componente, y decirlo con
precisión importa más que aproximarla: necesita un contador por IP de origen con
memoria entre flujos, y este componente recibe **un flujo terminado cada vez, sin
IP** —las características de identidad están excluidas del contrato por fuga de
datos, A1 §6.3— **y sin estado entre llamadas**. Ese contador sí existe en el
sistema: es la correlación del SOAR que agrupa flujos por IP en un caso. Pero vive
en el componente B, no es un clasificador, y no es lo que A5 compara.

La traducción honesta al espacio de 24 características es una regla de un solo
umbral sobre `flow_pkts_s` (posición 21): paquetes por segundo es la sombra, medida
por flujo, de «conexiones por segundo». Con la dirección que la regla implica:
**tasa alta = ataque**.

### 3.2 Qué se midió

Distribución de `flow_pkts_s` en el conjunto de entrenamiento:

| Percentil | BENIGN | ATTACK |
|---|---|---|
| 25 | 2,22 | 0,14 |
| **50 (mediana)** | **54,42** | **0,19** |
| 75 | 168,36 | 6,36 |
| 90 | 18.691,59 | 148,11 |

**Los ataques de este dataset son los flujos LENTOS.** Su mediana es 286 veces menor
que la del tráfico benigno.

La consecuencia, medida:

| Regla | Mejor F1 en entrenamiento |
|---|---|
| `flow_pkts_s >= 0,077608` → ATAQUE (la dirección del documento maestro) | 0,2858 |
| Óptimo exhaustivo en esa dirección, sobre los 1.009.166 valores distintos | 0,2861 |
| **Un clasificador que marca TODO como ataque** | **0,2857** |
| `flow_pkts_s <= 0,203715` → ATAQUE (la dirección contraria) | **0,6049** |

La regla tal y como está redactada vale 0,2861 y no marcar nada vale 0,2857. **No
distingue nada.** Se comprobó explícitamente que no era un fallo del barrido de
umbrales: el óptimo se buscó de forma exhaustiva sobre todos los valores distintos
observados, no sobre una rejilla.

### 3.3 Por qué ocurre

No es un defecto del dataset ni del preprocesamiento. Es lo que significan estos
ataques medidos por flujo:

- Un **DoS lento** funciona manteniendo conexiones abiertas y mandando lo mínimo
  para no cerrarlas. Pocos paquetes repartidos en mucho tiempo: tasa baja.
- Un **sondeo de escaneo de puertos** es un paquete, y el flujo que lo contiene
  espera después. Tasa baja.
- Una **descarga o una sesión web benigna** mueve muchos paquetes en poco tiempo.
  Tasa alta.

La intuición «ataque = mucho tráfico» es correcta **por IP de origen y por unidad de
tiempo**, que es como la mide el SOAR. Deja de serlo **por flujo**, que es lo único
que este componente ve. La regla no estaba mal pensada: estaba pensada para el otro
componente.

### 3.4 Qué se cambió, y por qué no es hacer trampa

`FixedRuleBaseline.fit()` barre **las dos direcciones** y se queda con la que mejor
F1 obtiene **sobre el conjunto de entrenamiento**. El informe imprime las dos
cifras, no solo la ganadora.

Es una desviación deliberada del enunciado original y se sostiene sobre tres puntos:

1. **No hay fuga.** Ni una sola fila del conjunto de prueba interviene en la
   elección, ni del umbral ni de la dirección. Es la misma restricción que se le
   impone a los otros dos modelos.
2. **Sigue siendo la misma clase de modelo.** Una característica, un umbral, salida
   0/1. No se le añadió capacidad, se le corrigió la orientación.
3. **La alternativa no demostraría nada.** Dejarla apuntada al revés y publicar que
   el aprendizaje automático le gana 0,99 a 0,29 sería ganarle a un espantapájaros
   construido por nuestra propia redacción. Un juez tiene derecho a suponer que la
   comparación se hizo contra la regla **en su mejor forma honesta**, y ahora se
   hizo.

**Lo que NO se cambió:** la regla sigue viendo una sola característica; no se le
permite elegir cuál, ni combinar varias, ni ajustar una dirección distinta por
familia de ataque. Eso último sí sería ajustarla a la respuesta.

**Y la conclusión del proyecto no depende de esto:** incluso en su mejor forma, la
regla fija se queda en **F1 = 0,6015** frente a **0,9920** del Random Forest, y deja
cuatro familias de ataque en cero o casi. La tesis se sostiene. Lo que cambia es el
ejemplo con el que se defiende.

---

## 4. Consecuencia: el argumento de la defensa hay que reescribirlo

Recall por familia sobre el conjunto de prueba. La fila BENIGN informa de la tasa de
falsos positivos, porque el recall de la clase ataque no está definido para ella.

| Familia | n | Random Forest | Logística | Regla fija |
|---|---|---|---|---|
| BENIGN *(tasa FP)* | 331.691 | **0,0023** | 0,0640 | 0,0382 |
| DoS Hulk | 34.365 | 0,9941 | 0,9061 | 0,8063 |
| DDoS | 25.599 | 0,9990 | 0,9982 | **0,1649** |
| DoS GoldenEye | 2.055 | 0,9859 | 0,7693 | 0,2414 |
| FTP-Patator | 1.186 | 0,9983 | **0,0008** | **0,0000** |
| DoS slowloris | 1.077 | 0,9926 | 0,8960 | 0,5840 |
| DoS Slowhttptest | 1.045 | 0,9952 | 0,9072 | 0,8517 |
| SSH-Patator | 630 | 0,9651 | **0,0000** | **0,0000** |
| PortScan | 385 | 0,9377 | 0,1325 | 0,0857 |

### 4.1 La expectativa previa no se cumple

Se esperaba que la regla fija **fallara en los ataques lentos** (`slowloris`,
`Slowhttptest`) y **acertara en los volumétricos** (`DoS Hulk`, `DDoS`). Lo medido
es casi lo contrario: la regla captura `DoS Slowhttptest` (0,85) y `slowloris`
(0,58), y **se hunde en `DDoS` (0,16)**.

Es coherente con §3.2. Al quedar la regla en «flujo lento = ataque», captura
exactamente los ataques que se predijo que se le escaparían.

**Corrección para A1 §4.7.** Aquella sección justifica la entrada de `flow_iat_max`
y `flow_iat_min` diciendo que suben la detección de los ataques lentos, «es decir el
escenario con el que vamos a argumentar que el ML le gana a la regla fija». La
primera mitad sigue siendo cierta y la segunda no: los ataques lentos son
precisamente donde la regla fija se defiende mejor.

### 4.2 El argumento que sí sostienen los datos

La regla fija no falla por ser lenta o rápida. **Falla porque una sola
característica no puede describir cuatro formas distintas de ataque.** Donde se ve:

- **`DDoS` 0,16 y `DoS GoldenEye` 0,24.** Ataques volumétricos que la regla debería
  ser capaz de ver y no ve, porque en su forma final busca lo contrario.
- **`FTP-Patator` y `SSH-Patator` en 0,0000.** La fuerza bruta no tiene una tasa
  característica; se delata por la **regularidad de los tamaños de paquete**, que la
  regla no mira. El Random Forest los detecta a 0,9983 y 0,9651.
- **`PortScan` 0,0857.** Un escaneo se delata por flujos minúsculos sin payload, no
  por su ritmo.

**El ML no gana por detectar mejor un ataque concreto. Gana porque cada familia se
delata por una característica distinta, y una regla de umbral solo puede mirar
una.** Ese es el argumento, y es más fuerte que el anterior.

Dato adicional para A5: la regresión logística también se anula en `FTP-Patator`
(0,0008) y `SSH-Patator` (0,0000) pese a un F1 global de 0,8151. **Un F1 agregado
puede esconder dos familias completas.** Es la razón por la que esta tabla existe.

---

## 5. Un defecto de despliegue encontrado por el camino

Al verificar los artefactos guardados, la línea base **no se podía cargar desde
ningún proceso distinto del que la entrenó**.

`joblib` serializa una clase por su **ruta de módulo**, no por su contenido. Al
ejecutar `train.py` como script, su módulo es `__main__`, de modo que el estimador
quedaba escrito en `models/` como `__main__.FixedRuleBaseline`: un nombre que no
resuelve en ningún otro intérprete. A5, el panel y el IDS en vivo habrían fallado
con `AttributeError`, **y solo en el momento de cargar el modelo**.

Corregido reentrando por el paquete en el bloque `__main__`, de forma que lo que se
ajusta y se serializa es `intelligence.train.FixedRuleBaseline`. Dos pruebas de
regresión lo fijan, una de ellas cargando el modelo en un intérprete nuevo mediante
un subproceso, que es donde el fallo se manifestaba.

Es el mismo patrón de fallo que el proyecto ya documentaba como crítico —el
`StandardScaler` que se pierde al serializar un estimador desnudo, y por el que el
escalador vive dentro del `Pipeline`— aplicado esta vez a la propia clase.

---

## 6. Lo que A4 deliberadamente no hizo

- **No elige ganador.** Eso es A5.
- **No ajusta el umbral.** Todo está al 0,5 por defecto. Eso es A6.
- **No dibuja nada.**
- **No ajusta hiperparámetros.** Los tres modelos van con los valores por defecto de
  scikit-learn. Un bosque ajustado contra una línea base sin ajustar no sería la
  comparación que A5 tiene que hacer.
- **No vuelve a preprocesar.** Si faltan los ficheros de `data/processed/`, el
  programa se detiene y lo dice, en lugar de regenerarlos: reconstruir el conjunto
  aquí desacoplaría en silencio estas cifras de las publicadas en la nota A3.
- **No remuestrea.** El desequilibrio se trata con `class_weight="balanced"` dentro
  del `Pipeline`, que es donde A1 decidió y A3 aplazó que viviera.

Una comprobación que sí hace, antes de ajustar nada: **verifica que las 24 columnas
llegan exactamente en el orden de `contract.FEATURES_24`**. Un vector permutado
entrenaría un modelo que lee `flow_duration` en la ranura de `tot_fwd_pkts`; todas
las métricas de este informe seguirían pareciendo plausibles y el extractor en vivo
—que emite el orden correcto— le daría al modelo algo que nunca vio. Es el único
error que ninguna métrica puede detectar, así que lleva una aserción.

---

## 7. Reproducción

Desde la raíz del repositorio, con el entorno virtual activo:

```bash
# Requiere que A3 se haya ejecutado antes:
#   python src/intelligence/preprocess.py --drop-duplicates

python src/intelligence/train.py     # ~4 min: validación cruzada + 3 ajustes
pytest -q                            # 100 pruebas
```

Semilla `random_state=42` en la partición, en los pliegues y en el bosque: toda la
cadena, del CSV crudo al modelo ajustado, se reproduce desde un solo número.

| Ruta | Qué es | ¿En git? |
|---|---|---|
| `scripts/scripts_output/train_report.txt` | La evidencia | **Sí** |
| `models/*.joblib` | Los tres `Pipeline` ajustados | No |
| `data/processed/test_predictions.parquet` | Predicciones sobre test, para A5 | No |

Cada modelo guarda `CONTRACT_VERSION` **en el mismo fichero**, y `load_model()`
rechaza cargar uno entrenado contra otra versión del contrato o contra otro orden de
características. Dos ficheros que hubiera que mantener sincronizados acabarían
desincronizados; uno solo no puede.

Las predicciones se guardan para que **A5 no tenga que reentrenar**: A5 es una tarea
de comparación, debería leer cifras, no dedicar veinte minutos a reproducirlas y
arriesgarse a reproducirlas ligeramente distintas. Verificado: los tres modelos
persistidos se cargan en un proceso limpio y reproducen exactamente esas
predicciones.

---

## 8. Qué queda abierto

- **A5 — comparar y elegir.** Con la tabla de §4, no solo con el F1 agregado. La
  línea base **no tiene curva ROC ni AUC**: una regla de umbral no produce ninguna
  noción de confianza, e inventarle una reescalando la característica fabricaría una
  curva que la regla no posee. Se compara con precisión, recall y F1.
- **A6 — el umbral.** El 0,5 de este informe es un marcador de posición. Y sigue en
  pie lo anotado en A3 §5.2: al eliminar duplicados cambió la frecuencia con que
  aparece cada patrón, así que las probabilidades del modelo están calibradas sobre
  una mezcla distinta de la de una captura cruda.
- **A7 — recalibrar con tráfico del laboratorio.** El riesgo de fondo sigue siendo
  el que identificó A1: **desfase de dominio**. Un F1 de 0,9920 sobre CICIDS2017 no
  es una promesa sobre la red del laboratorio, y §3 es la ilustración más clara de
  por qué: una intuición operativa perfectamente razonable resultó estar invertida
  en cuanto se midió sobre los datos reales.
