# Nota de umbral A6 — El punto de operación del sistema

**Tarea:** A6, convertir la probabilidad que emite el modelo en una política de
actuación.
**Contrato:** v1.0, sin cambios. El modelo está congelado; solo se mueve el corte.
**Decisión:** **dos niveles, 0,70 y 0,90.** Ya son los valores de `config.py`.
**Evidencia:** `scripts/scripts_output/threshold_report.txt`,
`reports/figures/threshold_curve.png`, `reports/figures/threshold_per_family.png`.

---

## 1. El punto de operación

| Probabilidad | Severidad | Acción | TTL |
|---|---|---|---|
| < 0,70 | — | ignorado, no se abre caso | — |
| 0,70 – 0,90 | **MEDIA** | contención corta | 300 s |
| ≥ 0,90 | **ALTA** | contención completa | 600 s |

Las cifras viven en `src/common/config.py`, que es el archivo compartido con el
componente B y **la única fuente de verdad**. `threshold.py` las lee y **se niega a
ejecutarse si han cambiado**, de modo que este informe no puede describir un punto de
operación distinto del que usa el sistema. Hay una prueba que lo fija.

### Por qué dos niveles y no uno

Los dos errores no cuestan lo mismo:

- Un **falso negativo** cuesta un flujo perdido, y el SOAR agrupa cientos de flujos
  por ataque en un solo caso. Un ataque sobrevive a muchos fallos.
- Un **falso positivo** dispara `iptables` contra un usuario real, y ese coste **no
  se diluye** con la agrupación.

Un corte único obliga a dar una sola respuesta a dos preguntas distintas. Con dos
niveles, un flujo dudoso cuesta cinco minutos de bloqueo y uno seguro cuesta diez.

---

## 2. Lo más importante que descubrió A6: el F1 no puede elegir

**El F1 de la clase ataque varía 0,0011 entre los umbrales 0,40 y 0,95** (de 0,9915 a
0,9926). Es plano. Y el análisis marginal —cuántos falsos positivos se ahorran por
cada ataque que se pierde— tampoco tiene codo: oscila entre 0,82 y 2,54 sin ningún
punto de inflexión.

> **A6 no es una optimización con respuesta correcta. Es una decisión de política
> acotada por la medición.** Decirlo así es más defendible que presentar un número
> elegido como si fuera un óptimo.

Lo que sí se mueve al desplazar el corte es el **reparto entre los dos errores**:

| Umbral | Precisión | Recall | FP | FN | FP/100k benignos |
|---|---|---|---|---|---|
| 0,50 | 0,9887 | 0,9953 | 757 | 314 | 228 |
| **0,70** | **0,9906** | **0,9934** | **626** | **439** | **189** |
| **0,90** | **0,9952** | **0,9901** | **319** | **657** | **96** |
| 0,99 | 0,9979 | 0,9810 | 140 | 1.260 | 42 |

---

## 3. Qué cae realmente en cada banda — y un hallazgo incómodo

Sobre los 398.033 flujos de prueba:

| Banda | Total | Ataques | Benignos | **Pureza** |
|---|---|---|---|---|
| Ignorado (< 0,70) | 331.504 | 439 | 331.065 | 0,0013 |
| **MEDIA [0,70–0,90)** | **525** | **218** | **307** | **0,4152** |
| ALTA (≥ 0,90) | 66.004 | 65.685 | 319 | 0,9952 |

### La banda media es mayoritariamente ruido

Contiene 525 de 398.033 flujos y su pureza es **0,4152**: **307 benignos frente a 218
ataques**. Contada flujo a flujo, **bloquea más tráfico legítimo del que detecta**.

La causa es que la salida del modelo es **fuertemente bimodal**: casi todo flujo cae
claramente por debajo de 0,70 o claramente por encima de 0,90. La franja intermedia
no es una población «dudosa» real, es una astilla estrecha y ruidosa.

Composición de la banda media:

| | Flujos |
|---|---|
| BENIGN | 307 |
| DoS Hulk | 77 |
| DoS Slowhttptest | 50 |
| PortScan | 34 |
| DDoS | 31 |
| DoS GoldenEye | 10 |
| SSH-Patator | 6 |
| DoS slowloris | 6 |
| FTP-Patator | 4 |

### Consecuencia operativa, y es una condición, no un matiz

> **La banda media solo es defendible si el SOAR exige más de un flujo para abrir un
> caso.** Un único flujo benigno en 0,75 no puede bloquear a nadie. Un atacante
> aporta muchos flujos, y la mayoría caen en la banda alta.

Esa regla de apertura de caso pertenece al componente B y **sigue sin decidirse**.
Mientras no se decida, **la banda media debe operar en modo `monitor`, no `enforce`**.
Es la palanca más barata que tiene el proyecto contra los falsos positivos, y es de
Frank.

---

## 4. Por qué no se sube más el corte

El recall agregado es plano, pero **las familias no lo son**. Elegir el umbral
mirando solo el agregado sería repetir exactamente el error que A5 documentó.

| Familia | n | 0,50 | **0,70** | 0,90 | 0,99 |
|---|---|---|---|---|---|
| DoS Hulk | 34.365 | 0,9942 | **0,9924** | 0,9902 | 0,9836 |
| DDoS | 25.599 | 0,9990 | **0,9987** | 0,9975 | 0,9952 |
| DoS GoldenEye | 2.055 | 0,9859 | **0,9781** | 0,9732 | 0,9328 |
| FTP-Patator | 1.186 | 0,9983 | **0,9949** | 0,9916 | 0,9798 |
| DoS slowloris | 1.077 | 0,9926 | **0,9926** | 0,9870 | 0,9777 |
| DoS Slowhttptest | 1.045 | 0,9952 | **0,9856** | 0,9378 | **0,8010** |
| SSH-Patator | 630 | 0,9667 | **0,9587** | 0,9492 | 0,9254 |
| PortScan | 385 | 0,9429 | **0,8779** | 0,7896 | **0,6597** |
| BENIGN *(tasa FP)* | 331.691 | 0,0023 | **0,0019** | 0,0010 | 0,0004 |

**En 0,70 ninguna familia baja de 0,87.** En 0,99, `PortScan` cae a 0,6597 y
`DoS Slowhttptest` a 0,8010 — las dos familias más pequeñas, y una de ellas es
escenario de la demo.

### El contraargumento, dicho entero

Hay que ser honesto: **el recall por flujo no es el recall del ataque.** Un escaneo de
100 flujos con recall 0,6597 se pierde entero con probabilidad 0,34¹⁰⁰, que no es un
número que ocurra. Así que **la razón para quedarse en 0,70 no es que 0,99 fuera a
perder escaneos** — no los perdería.

Las razones reales son tres:

1. **Bajar el corte cuesta poco.** De 0,90 a 0,70 se ganan 307 falsos positivos sobre
   331.691 flujos benignos: 0,09 puntos porcentuales.
2. **Mantiene vivas las bandas de severidad.** Con el umbral en 0,90, `SEV_MEDIUM` =
   0,70 quedaría por debajo del umbral —banda muerta— y todo lo detectado sería
   severidad alta. La respuesta graduada desaparecería.
3. **Deja margen para el desfase de dominio.** Un umbral afinado al último decimal
   sobre CICIDS2017 sería precisión falsa sobre una red que todavía no hemos medido.
   A7 va a mover esto.

---

## 5. Lo que A6 no arregla: la tasa base

El conjunto de prueba es **16,67 % ataques**. Una red real entre ataques no se parece
a eso, y la precisión depende de ello. Mismo modelo, mismo corte, otra aritmética:

| Umbral | Recall | FPR | prev. 16,67 % | prev. 1 % | prev. 0,1 % |
|---|---|---|---|---|---|
| 0,50 | 0,9953 | 0,00228 | 0,9887 | 0,8150 | 0,3039 |
| **0,70** | **0,9934** | **0,00189** | **0,9906** | **0,8417** | **0,3451** |
| 0,90 | 0,9901 | 0,00096 | 0,9952 | 0,9123 | 0,5075 |
| 0,99 | 0,9810 | 0,00042 | 0,9979 | 0,9591 | 0,6994 |

En el corte elegido el modelo produce **189 falsas alarmas por cada 100.000 flujos
benignos**, sea cual sea la prevalencia. Cuando los ataques son el 0,1 % del tráfico,
esas 189 sepultan a los verdaderos positivos y la precisión cae a **0,3451**.

**Ningún umbral arregla esto: es aritmética, no un defecto del modelo.** Lo arreglan
dos cosas, y ninguna es de A6:

1. Que el **SOAR exija varios flujos de la misma IP** antes de abrir un caso (§3).
2. Que **A7 mida la tasa de falsos positivos sobre el tráfico benigno del
   laboratorio**, que nunca se ha medido.

Es la razón de fondo por la que el sistema tiene `MODE = monitor | alert | enforce`:
para poder observar antes de bloquear.

---

## 6. Reproducción

```bash
# Requiere A4 (los modelos y las predicciones ya persistidos)
python src/intelligence/threshold.py
pytest -q
```

No reentrena nada: lee `data/processed/test_predictions.parquet`. Coste: ~15 s.

| Ruta | Qué es | ¿En git? |
|---|---|---|
| `scripts/scripts_output/threshold_report.txt` | La evidencia | **Sí** |
| `reports/figures/threshold_curve.png` | Precisión, recall y FP frente al corte | **Sí** |
| `reports/figures/threshold_per_family.png` | Recall por familia frente al corte | **Sí** |

---

## 7. Qué queda abierto

- **Regla de apertura de caso (componente B, Frank).** Cuántos flujos de una misma IP
  hacen falta para abrir un caso. **Condiciona si la banda media puede pasar a
  `enforce`** (§3) y es la defensa más barata contra los falsos positivos.
- **A7 — recalibrar con tráfico del laboratorio.** El umbral de este documento está
  medido sobre CICIDS2017. Las dos cosas que A7 debe medir y que hoy no existen: la
  **tasa de falsos positivos sobre tráfico benigno del laboratorio**, y si un
  `hping3 -S` cae donde el modelo espera encontrar un `DDoS` (ver
  `A5_evaluation_note.md` §6.3: el desfase se concentra en la inundación, no en el
  escaneo).
- **Ventanas parciales.** El contrato dice que se evaluarán flujos incompletos cada
  pocos segundos, y el modelo solo ha visto flujos terminados. El umbral de este
  documento está medido sobre flujos completos y **no se ha comprobado que valga para
  ventanas parciales**. `src/system/pipeline.py` sigue vacío, así que es el momento de
  decidirlo.
