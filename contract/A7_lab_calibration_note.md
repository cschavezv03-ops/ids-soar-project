# Nota A7 (primera pasada) — El modelo contra el tráfico del laboratorio

**Tarea:** A7, recalibrar con tráfico propio. **Esta nota cubre la mitad medible hoy.**
**Contrato:** v1.0, sin cambios. **`config.py` sin tocar:** no se ha movido ningún umbral.
**Evidencia:** `scripts/scripts_output/lab_calibration_report.txt`.

> **Resultado, sin rodeos: al punto de operación de A6 (0,70), el modelo no detecta
> los ataques del laboratorio.** Escaneo lento 6,8 %, escaneo rápido 0,9 %, SYN flood
> 0,0 %, fuerza bruta SSH 0,0 %. El F1 de 0,9920 sobre CICIDS2017 no se traslada.
>
> Esto es exactamente el **desfase de dominio** que A1 identificó como riesgo
> principal del proyecto y que A5 §6.3 predijo con su dirección. No es una sorpresa:
> es la razón por la que A7 existe. Pero es una condición de bloqueo para la demo y
> hay que tratarla como tal.

---

## 1. Lo que se midió

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

## 2. El diagnóstico que importa: no es un solo problema, son dos

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

## 3. Un defecto de captura que hay que corregir antes de seguir

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

## 4. La otra mitad de A7 sigue bloqueada

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

## 5. Alcance de A7: recalibrar es mover el umbral, no reentrenar

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

## 6. Reproducción

```bash
python src/intelligence/lab_calibration.py   # ~2 min, ningun reentrenamiento
pytest -q                                    # 125 pruebas
```

Lee los pcaps de `data/pcap/`, el modelo de `models/` y las medianas por familia de
`data/processed/train.parquet`. Reutiliza `extract_all` de `scripts/profile_pcap.py`,
que es la extracción que A2 validó — una segunda copia acabaría divergiendo.

---

## 7. Qué queda, en orden

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
