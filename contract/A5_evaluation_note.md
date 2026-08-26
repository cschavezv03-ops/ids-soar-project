# Nota de evaluación A5 — Comparación y elección del modelo final

**Tarea:** A5, convertir las cifras de A4 en una decisión con evidencia detrás.
**Contrato:** v1.0, sin cambios.
**Decisión:** **Random Forest.**
**Evidencia:** `scripts/scripts_output/eval_report.txt`, `reports/figures/`.

> **Todas las cifras de este documento están tomadas al umbral de decisión 0,5**,
> el valor por defecto de scikit-learn. Ese **no** es el punto de operación del
> sistema: lo fija A6. Un F1 citado sin el umbral al que se midió no es un número
> reproducible, así que el umbral se declara en cada tabla en lugar de darse por
> supuesto.

A5 no reentrena nada. Carga los tres modelos que persistió A4 y sus predicciones
guardadas, y rechaza cualquier modelo cuya `CONTRACT_VERSION` u orden de
características no coincidan con los de este código.

---

## 1. La comparación: cuatro filas para tres modelos

| Modelo | Precisión | Recall | **F1** | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|
| **Random Forest** | 0,9888 | 0,9952 | **0,9920** | 0,9994 | 0,9979 |
| Regresión logística | 0,7395 | 0,9080 | 0,8151 | 0,9839 | 0,9391 |
| Regla fija — dirección **INGENUA** (`flow_pkts_s >=`) | 0,1672 | 0,9857 | 0,2859 | — | — |
| Regla fija — dirección **AJUSTADA** (`flow_pkts_s <=`) | 0,7285 | 0,5122 | 0,6015 | — | — |

La regla fija **no tiene ROC-AUC ni PR-AUC**, y esas casillas están vacías, no a
cero. Una regla de umbral emite 0/1: no ordena los flujos por confianza, así que no
hay ninguna curva que integrar. Inventarle una puntuación —reescalando la
característica, por ejemplo— fabricaría una curva que la regla no posee y la
favorecería frente a los modelos que sí la producen.

**Por qué se publican las dos direcciones.** Son la misma regla apuntada en
sentidos opuestos. La ingenua es la que asumía el enunciado del proyecto; la
ajustada, elegida **solo sobre datos de entrenamiento**, es la comparación que
significa algo. Publicar una sola sería deshonesto en un sentido o en el otro.
Ninguno de los dos umbrales se ajustó aquí: A4 eligió ambos y A5 los lee del modelo
guardado.

**Cómo NO leer la fila ingenua.** En la tabla por familia (§4) esa columna marca
1,0000 en los dos Patator y 0,9998 en DDoS, y parece el mejor detector de todos.
Alcanza esas cifras marcando **391.014 de 398.033 flujos** como ataque, incluidos
**325.624 de los 331.691 benignos**: una tasa de falsos positivos de **0,9817**. Su
recall es alto por la misma razón por la que una alarma que suena siempre tiene
recall perfecto. Para escala: un clasificador que marca **todo** como ataque obtiene
F1 = 0,2857, y la regla ingenua obtiene 0,2859.

---

## 2. Por qué Random Forest

| Criterio | Random Forest | Logística | Regla fija |
|---|---|---|---|
| F1 en test (clase ataque) | **0,9920** | 0,8151 | 0,6015 |
| PR-AUC | **0,9979** | 0,9391 | — |
| Estabilidad en validación cruzada (σ, 5 pliegues) | **0,0008** | 0,0020 | 0,0049 |
| Brecha entrenamiento − prueba (F1) | **0,0045** | — | — |
| Tasa de falsos positivos | **0,0023** | 0,0640 | 0,0382 |
| Familias con recall < 0,50 | **0** | 2 | 4 |

1. **Rendimiento.** 0,9920 frente a 0,8151 y 0,6015. No es un margen discutible.
2. **Estabilidad.** σ = 0,0008 entre los cinco pliegues. El resultado no es un
   artefacto de una partición afortunada.
3. **Sin sobreajuste apreciable.** F1 de 0,9965 en entrenamiento y 0,9920 en prueba:
   **brecha de 0,0045**. Un bosque sin límite de profundidad ajusta el entrenamiento
   casi a la perfección por construcción, de modo que la brecha se espera; lo
   relevante es que sea de milésimas y que la cifra de prueba se sostenga.
4. **Ninguna familia abandonada.** Su peor recall por familia es 0,9377 (PortScan).
   Es el único de los tres que detecta las nueve familias, y es el criterio que
   realmente decide (§4).
5. **Coste operativo del error.** 751 falsos positivos sobre 331.691 flujos
   benignos, frente a 12.661 de la regla fija y 21.223 de la logística.

### Por qué PR-AUC y no ROC-AUC

El conjunto de prueba es 16,67 % ataques. La curva ROC enfrenta el recall con la
**tasa de falsos positivos**, cuyo denominador son los 331.691 flujos benignos: miles
de falsos positivos apenas la mueven y todos los modelos parecen excelentes.
Precision-Recall usa la precisión, cuyo denominador es lo que el modelo marcó, así
que se degrada en cuanto el modelo empieza a alarmar sobre tráfico normal.

El nivel de azar lo deja claro: **ROC-AUC de una moneda = 0,5000; PR-AUC de una
moneda = 0,1667** (la prevalencia). Un ROC-AUC de 0,99 dice «mejor que una moneda».
Un PR-AUC de 0,99 dice «seis veces el suelo de prevalencia». Solo el segundo
informa. Se ve en las figuras: en `roc_curves.png` las dos curvas se pegan a la
esquina y casi no se distinguen; en `pr_curves.png` se separan visiblemente.

---

## 3. La matriz de confusión, traducida a lo que significa

Sobre 398.033 flujos de prueba (331.691 benignos, 66.342 de ataque):

| Modelo | Falsos positivos | Falsos negativos |
|---|---|---|
| Random Forest | **751** usuarios legítimos bloqueados | **319** flujos de ataque que llegaron al host |
| Regresión logística | 21.223 | 6.105 |
| Regla fija (ajustada) | 12.661 | 32.364 |

Las dos celdas de error **no son intercambiables** y el sistema no las trata como
tales:

- Un **falso negativo** cuesta un flujo perdido. El SOAR agrupa cientos de flujos
  por ataque en un solo caso, así que un ataque sobrevive a muchos fallos: los 319
  del bosque no equivalen a 319 ataques no detectados.
- Un **falso positivo** dispara `iptables` contra un usuario real. Su coste no se
  diluye por agrupación: cada uno corta a alguien.

Esta asimetría es exactamente la perilla que A6 va a mover, y la razón por la que
mover el umbral no es una optimización cosmética.

---

## 4. Recall por familia — la tabla que decide

Recalculada desde `data/processed/test_predictions.parquet`, no copiada del informe
de A4, para que sea verificable solo con los artefactos. La fila BENIGN es una
**tasa de falsos positivos**: el recall de la clase ataque no está definido para ella.

| Familia | n | Random Forest | Logística | Regla INGENUA | Regla AJUSTADA |
|---|---|---|---|---|---|
| BENIGN *(tasa FP)* | 331.691 | **0,0023** | 0,0640 | 0,9817 | 0,0382 |
| DoS Hulk | 34.365 | 0,9941 | 0,9061 | 0,9964 | 0,8063 |
| DDoS | 25.599 | 0,9990 | 0,9982 | 0,9998 | **0,1649** |
| DoS GoldenEye | 2.055 | 0,9859 | 0,7693 | 0,8044 | 0,2414 |
| FTP-Patator | 1.186 | 0,9983 | **0,0008** | 1,0000 | **0,0000** |
| DoS slowloris | 1.077 | 0,9926 | 0,8960 | 0,7632 | 0,5840 |
| DoS Slowhttptest | 1.045 | 0,9952 | 0,9072 | 0,8622 | 0,8517 |
| SSH-Patator | 630 | 0,9651 | **0,0000** | 1,0000 | **0,0000** |
| PortScan | 385 | 0,9377 | 0,1325 | 0,9377 | **0,0857** |

### Hallazgo 1 — la regla fija anula cuatro familias enteras

`FTP-Patator` 0,0000, `SSH-Patator` 0,0000, `PortScan` 0,0857, `DDoS` 0,1649.
**Ninguna de las cuatro se separa del tráfico normal por su TASA:**

- la **fuerza bruta** se delata por lo regular de sus tamaños de paquete;
- un **escaneo de puertos**, por flujos minúsculos que no transportan payload;
- **DDoS** cae al lado equivocado de una regla que acabó significando «flujo lento
  = ataque».

Esta es la forma medida del argumento central del proyecto. **La regla no falla por
ser un modelo simple: falla porque una sola característica no puede describir cuatro
formas distintas de ataque, y un umbral solo puede mirar una.**

### Hallazgo 2 — un agregado puede esconder dos familias completas

La regresión logística obtiene **F1 = 0,8151**, que se lee como un modelo
respetable, mientras puntúa **0,0008 en FTP-Patator y 0,0000 en SSH-Patator**. Las
dos son escenarios de la demo. Un único número de titular habría concluido que el
modelo lineal es suficiente. Esta tabla es la razón concreta por la que este proyecto
no evalúa con una sola cifra.

---

## 5. El argumento de la defensa, corregido

El enunciado del proyecto predecía que la regla fija **fallaría en los ataques
lentos y acertaría en los ruidosos**. La medición muestra casi lo contrario.

**La causa, en una línea:** la mediana de `flow_pkts_s` es **0,19 en ataques** y
**54,42 en tráfico benigno**. Un DoS mantiene conexiones abiertas mandando lo mínimo
para no cerrarlas, y una inundación es muchos flujos escasos; el tráfico web normal
son peticiones cortas y rápidas. Medido **por flujo**, los ataques de este dataset
tienden a ser los lentos.

Así que la regla, al ajustar su dirección, acabó significando «flujo lento =
ataque». Y por eso **captura** `DoS Slowhttptest` (0,85) y `slowloris` (0,58) —
justo lo que se predijo que perdería— y **se hunde** en `DDoS`, `PortScan` y los dos
Patator.

**Dos precisiones que no conviene omitir en la defensa.**

*Primera: «los ataques son lentos» aguanta, con una excepción.* Ocho de las nueve
familias tienen mediana por debajo de la benigna; solo `PortScan` (5.017 pkts/s) va
en sentido contrario. La tabla completa está en §6.1.

*Segunda, y es la que explica el fracaso: la regla no falla por la dirección, falla
por el solapamiento.* Su umbral (`<= 0,2037`) es tan bajo que solo captura las tres
variantes de DoS más lentas. Subirlo para alcanzar a `SSH-Patator` (4,41) exigiría
llegar a 5, y ahí arrastraría 393.705 flujos benignos. **No existe ningún punto donde
colocar un solo corte** (§6.2). El argumento no cambia — una característica no
describe nueve formas de ataque — pero el mecanismo es el solapamiento, no la
velocidad.

**La conclusión no cambia: una característica no basta, 0,60 frente a 0,99.** Lo
único que se movió es el ejemplo con el que se ilustra. El guion de la defensa ya no
es «la regla no ve los ataques lentos», sino **«cada familia se delata por una
característica distinta y un umbral solo puede mirar una»** — que es un argumento
más fuerte, porque no depende de qué ataque se elija para la demo.

### Por qué se ajustó la dirección en lugar de tomarla del enunciado

Porque comparar contra una línea base degenerada no demuestra nada. En la dirección
del enunciado la regla puntúa 0,2859 y marcar todo como ataque puntúa 0,2857: no
distingue nada. Publicar que el aprendizaje automático le gana 0,99 a 0,29 sería
ganarle a un espantapájaros construido por nuestra propia redacción.

La dirección se eligió **solo con datos de entrenamiento**, la misma restricción que
se impone a los otros dos modelos, y la regla sigue viendo **una sola
característica**: no se le permite elegir cuál, ni combinar varias, ni usar una
dirección distinta por familia. Eso último sí sería ajustarla a la respuesta.
Desarrollo completo en `A4_training_note.md` §3.

---

## 6. Desfase de dominio: el riesgo, y esta vez con la dirección conocida

**Esta es la limitación más importante del documento y no se resuelve con más
métricas offline.**

### 6.1 Qué aprendió el modelo sobre la velocidad, dicho con cuidado

Medido **por flujo**, el tráfico de ataque de este dataset es más lento que el
normal. No es un detalle de una familia concreta: **ocho de las nueve familias
tienen una mediana de `flow_pkts_s` por debajo de la mediana benigna.**

| Familia | Flujos | Mediana pkts/s | ¿Más lenta que benigno? |
|---|---|---|---|
| BENIGN | 1.326.763 | **54,42** | — |
| DoS Hulk | 137.457 | 0,15 | Sí |
| DDoS | 102.397 | 2,55 | Sí |
| DoS GoldenEye | 8.221 | 0,98 | Sí |
| FTP-Patator | 4.743 | 2,76 | Sí |
| DoS slowloris | 4.305 | 0,18 | Sí |
| DoS Slowhttptest | 4.182 | 0,11 | Sí |
| SSH-Patator | 2.521 | 4,41 | Sí |
| **PortScan** | 1.540 | **5.017,49** | **No — la excepción** |

**Por qué una inundación aparece como "lenta".** No es que el ataque sea lento: es
que una inundación son **muchos flujos escasos**. `DDoS` son unos 8 paquetes en 1,9
segundos *por flujo*. El caudal enorme existe, pero solo aparece al **sumar todos los
flujos de una misma IP**, que es lo que hace el SOAR y no lo que puede ver una
característica calculada dentro de un flujo aislado.

`PortScan` es la excepción y conviene tenerla presente: 5.017 pkts/s, 92 veces la
mediana benigna. Un escaneo sí es rápido incluso mirando un flujo suelto.

### 6.2 Por qué un solo umbral fracasa aunque apunte en la dirección correcta

Este es el argumento del proyecto, y **no depende de la dirección**. Las
distribuciones se solapan: no existe ningún sitio donde poner un único corte.

| Umbral | Captura de ataques | Arrastra de tráfico benigno |
|---|---|---|
| `<= 0,2037` (el que maximiza F1) | 51,6 % | 3,8 % — **50.555 flujos** |
| `<= 1,0` | 62,7 % | 19,0 % — 252.297 flujos |
| `<= 3,0` | 69,6 % | 27,6 % — 366.390 flujos |
| `<= 5,0` | 73,2 % | 29,7 % — **393.705 flujos** |

Para alcanzar a `SSH-Patator` (4,41) haría falta un umbral de 5, y ahí ya se estarían
bloqueando 393.705 flujos legítimos. Las familias se reparten entre 0,11 y 5.017
pkts/s, y el tráfico benigno está presente en todo ese rango.

**Aunque la dirección hubiera sido la del enunciado desde el principio, la conclusión
sería idéntica:** una sola característica no separa nueve poblaciones solapadas. Eso,
y no la velocidad, es lo que exige un modelo.

### 6.3 Dónde está el desfase de dominio, entonces

| Herramienta del laboratorio | Lo que el modelo vio en CICIDS2017 | ¿Coincide? |
|---|---|---|
| `nmap -sS -T4` | `PortScan` ya es rápido y ruidoso: 5.017 pkts/s, 0,001 s | **Sí**, el perfil se parece |
| `hping3 -S` | `DDoS` mide 2,55 pkts/s **por flujo** | **No**: la inundación del laboratorio será mucho más rápida por flujo |

El riesgo se concentra en la **inundación**, no en el escaneo — al revés de lo que
una lectura rápida de "los ataques son lentos" sugeriría.

**Un mecanismo relacionado, acotado con su magnitud.** La regla R3 convierte los no
finitos en 0,0, así que un flujo de duración cero produce división por cero en
`flow_pkts_s` y aterriza en 0,0, indistinguible de un flujo lentísimo. Medido sobre
el entrenamiento, **ocurre en 1 flujo de `PortScan`, 1 de `DDoS` y 30 benignos**: el
mecanismo existe pero hoy es numéricamente irrelevante. Se registra porque en el
laboratorio, con capturas cortas y sondeos aislados, podría dejar de serlo. R3 no se
toca: es bidireccional y garantiza que entrenamiento e inferencia traten los no
finitos igual.

**Nada cambia ahora.** Esto determina dos cosas aguas abajo:

1. **Qué capturas pedirle a Frank en A7.** Hacen falta capturas benignas *rápidas*
   —descargas, navegación intensa— para comprobar si el modelo las marca como
   ataque. La nota A2 §5 ya advertía de que las capturas benignas actuales son
   flujos únicos y largos, que es el caso fácil.
2. **Por qué existe la recalibración del umbral.** No es un ajuste fino: es la
   respuesta prevista a un desfase cuya dirección ya conocemos.

---

## 7. Límites honestos de este resultado

- **0,9920 es una cifra offline sobre CICIDS2017 en 2017.** No es una afirmación
  sobre el tráfico del laboratorio. La prueba real es A7.
- **Todo está al umbral 0,5**, que es un valor por defecto, no una decisión. A6
  mueve esa perilla, y con la asimetría de coste de §3 delante.
- **Las proporciones son las del dataset deduplicado** (decisión D3, `A3` §5.1).
  `PortScan` aporta 385 flujos al conjunto de prueba: su recall de 0,9377 es la
  cifra con el intervalo de confianza más ancho de la tabla, y la primera a vigilar
  si algo se degrada.
- **La regla fija se compara solo por precisión, recall y F1.** No tiene curvas, y
  no se le fabricaron.

---

## 8. Qué queda abierto

- **A6 — el umbral.** Con la curva PR de `reports/figures/pr_curves.png` y la
  asimetría de coste de §3. Sigue en pie lo anotado en `A3` §5.2: al eliminar
  duplicados cambió la frecuencia con que aparece cada patrón, así que las
  probabilidades están calibradas sobre una mezcla distinta de la de una captura
  cruda.
- **A7 — recalibrar con tráfico propio**, con la dirección del desfase de §6 ya
  identificada.
- **Umbral y severidad.** De `A1` §9: si el umbral baja de 0,70, hay que revisar con
  Frank los cortes `SEV_MEDIUM` y `SEV_HIGH` de `config.py`.
