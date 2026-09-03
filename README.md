# IDS + SOAR — Detección de intrusiones de red con respuesta automática

Sistema de detección de intrusiones que clasifica tráfico de red mediante aprendizaje
automático y ejecuta una respuesta de contención automática (SOAR) sobre las conexiones
que identifica como maliciosas.

**Proyecto académico** · Fundamentos de Inteligencia Artificial · Summer Camp 2026 ·
CyberMinds, Escuela Politécnica Nacional (Quito).

---

## Qué hace

El sistema no analiza paquetes sueltos: los agrupa en **flujos** —conversaciones
completas entre dos máquinas, identificadas por la 5-tupla (IP origen, IP destino,
puerto origen, puerto destino, protocolo)—, describe cada flujo mediante un vector de
24 características numéricas, lo puntúa con un clasificador y decide qué hacer.

```
   Paquetes en vivo                    CICIDS2017 (CSV etiquetado)
         │                                        │
         ▼                                        ▼
    FlowManager                            preprocess ─► train ─► evaluate
   (ensambla flujos)                                              │
         │                                                        ▼
         ▼                                                   threshold
   24 características ◄──── mismo contrato ────►             recalibrate
         │                                                        │
         ▼                                                        ▼
    predict()  ◄───────────── Random Forest ◄──────────────  models/
         │
         ▼
  SOAR: alerta ─► caso ─► severidad ─► playbook
         │
         ▼
  Contención: ipset + iptables, con expiración en el kernel
         │
         ▼
  Panel (Streamlit): casos, severidades, bloqueos activos, modo
```

### Escenarios de ataque cubiertos

Escaneo de puertos (rápido y lento), denegación de servicio (Hulk, GoldenEye,
slowloris, Slowhttptest), denegación distribuida y fuerza bruta contra SSH y FTP.

---

## Resultados

Modelo elegido: **Random Forest**, comparado contra regresión logística y contra una
regla fija de umbral sobre una sola característica.

| Métrica (partición de prueba) | Valor |
|---|---|
| F1, clase ataque | **0,9920** |
| PR-AUC | 0,9979 |
| Tasa de falsos positivos | 0,0023 |
| Peor recall por familia | 0,9377 (PortScan) |
| Estabilidad en validación cruzada | σ = 0,0008 sobre 5 particiones |

La comparación está en `scripts/scripts_output/eval_report.txt`. Dos hallazgos que
justifican no evaluar con una sola cifra agregada:

- La regla fija de umbral no falla por ser un modelo simple, sino porque **una sola
  característica no puede describir cuatro formas distintas de ataque**.
- La regresión logística puntúa F1 0,8151 en agregado y **0,0000 en SSH-Patator**: un
  titular único habría concluido que era adecuada.

### Umbral de decisión

Fijado en **0,50** (severidad alta a partir de 0,70), recalibrado contra 12 029 flujos
benignos reales del laboratorio. Los valores originales (0,70 / 0,90), fijados solo
sobre CICIDS2017, detectaban el 0,6 % de nuestro propio escaneo de puertos; 0,50 detecta
el 57 %. La banda alta baja a 0,70 porque **ningún flujo de ataque del laboratorio
alcanza 0,90**: una banda ahí estaría muerta en nuestra red.

### Un límite que el sistema documenta en lugar de ocultar

La inundación SYN del laboratorio (`hping3 -S`) es una **inundación no respondida**: un
paquete de ida, nada de vuelta, duración cero. La familia DDoS de CICIDS2017 es una
inundación HTTP **respondida**: cuatro paquetes en cada sentido y 11 601 bytes de
respuesta del servidor. Comparten el nombre y nada más.

CICIDS2017 contiene **cero** flujos con la firma de nuestra inundación. No pocos:
ninguno. El modelo, por tanto, no se equivoca al clasificarla: **extrapola** hacia una
región del espacio de características que su entrenamiento nunca cubrió, y ningún umbral
repara una región que no se aprendió.

La respuesta de diseño es la que encaja con la arquitectura: **el modelo aporta la forma
del flujo, el SOAR aporta el caudal.** Una inundación se distingue contando conexiones
por IP y por unidad de tiempo, que es exactamente lo que hace la correlación por tasa del
motor SOAR.

---

## El contrato de características: el punto de acople

El sistema tiene dos mitades que se desarrollan por separado y se tocan en **un único
punto**: un contrato de 24 características numéricas, en orden congelado, que debe
significar **lo mismo** durante el entrenamiento (CSV de CICIDS2017) y durante la
inferencia en vivo (tráfico capturado en el laboratorio).

Esa propiedad se llama **paridad**. Si los dos caminos difieren, el modelo aprende sobre
una realidad y decide sobre otra: no se lanza ningún error, las métricas de evaluación
salen excelentes y el sistema falla en la demostración.

| Grupo | Posiciones | Qué distingue |
|---|---|---|
| Duración y volumen | 0–4 | Un escaneo (flujos minúsculos) frente a una inundación |
| Tamaños de paquete, ida | 5–8 | La fuerza bruta produce tamaños muy regulares |
| Tamaños de paquete, vuelta | 9–12 | Si la conversación es real o solo sondeo |
| Tamaños del flujo completo | 13–14 | Resumen global en ambos sentidos |
| Ritmo temporal | 15–20 | El escaneo lento: espaciado artificial entre paquetes |
| Tasas y datos útiles | 21–23 | Velocidad y si transporta contenido real |

La fuente única de verdad es [`src/intelligence/contract.py`](src/intelligence/contract.py).
La justificación completa —cómo se pasó de 78 candidatas a 24, por qué se excluyeron las
banderas TCP y la ventana inicial, y las cuatro reglas de normalización (R1–R4)— está en
[`contract/contract_characteristics.md`](contract/contract_characteristics.md).

**Contrato congelado en v1.0.** Cambiar el número de características, su orden o sus
unidades rompe la interfaz entre las dos mitades y exige subir la versión.

### La interfaz entre las dos mitades

```python
extract_features(flow) -> list[float]   # 24 valores, orden congelado
predict(feature_vector) -> float        # probabilidad de ataque, 0.0 a 1.0
```

Todo lo que hay detrás de `predict()` —qué modelo, qué umbral, qué versión del
contrato— puede cambiar sin tocar el código del componente B, mientras la firma se
mantenga. El modelo se carga una sola vez y se cachea, y **rechaza cargarse** si la
versión del contrato o el orden de características almacenados no coinciden con el
código: un modelo emparejado con el contrato equivocado leería sus 24 entradas en las
casillas equivocadas y todas sus puntuaciones serían erróneas de una forma que ninguna
métrica revela.

---

## Los parches de `cicflowmeter`

La herramienta que convierte tráfico en características, `cicflowmeter 0.5.0`, presenta
**tres defectos y una divergencia de definición** frente al dataset de referencia. Se
detectaron validando la herramienta contra una captura sintética de verdad conocida,
**antes** de entrenar nada con ella.

| | Qué ocurre | Decisión |
|---|---|---|
| Defecto 1 | La interfaz de línea de comandos falla siempre: argumentos posicionales desplazados | Corregir |
| Defecto 2 | El primer paquete de cada flujo se contabiliza dos veces | Corregir |
| Defecto 3 | Todo flujo de dos paquetes informa tiempo entre paquetes cero | Corregir |
| Regla R2 | La longitud de paquete se mide como trama; el CSV la mide como payload | **Replicar el CSV**, no corregirlo |

Los tres primeros son errores de la reimplementación en Python. El cuarto no lo es: es
una divergencia entre dos implementaciones defendibles, y quien se aparta de la
definición estricta es el CSV. Se replica en lugar de corregirse **por el mismo
criterio** que motivó corregir los otros tres: la paridad se define contra el CSV sobre
el que el modelo aprende, no contra la corrección matemática.

Las correcciones son sustituciones en tiempo de ejecución. **La librería no se modifica
en disco:** viven en [`src/intelligence/cicflowmeter_patches.py`](src/intelligence/cicflowmeter_patches.py),
tras una función `apply_patches()` idempotente. El informe técnico completo, con la
evidencia sobre las 2 830 743 filas del dataset, está en
[`copilot/cicflowmeter_bugs.md`](copilot/cicflowmeter_bugs.md).

---

## Estructura del repositorio

```
contract/     Contrato de características y bitácora de decisiones (A1–A7)
copilot/      Informe de defectos y bitácora del laboratorio (B0–B2)
scripts/      Auditorías, verificaciones y sus salidas en scripts_output/
src/
  common/       config.py — parámetros compartidos por las dos mitades
  capture/      Flow y FlowManager: paquetes → flujos
  intelligence/ Contrato, extractor, preprocesamiento, entrenamiento,
                evaluación, umbral, recalibración y modelo
  system/       Captura en vivo, pipeline de inferencia, SOAR, contención, panel
tests/        Pruebas del contrato, los parches, el extractor, el modelo,
              el ensamblado de flujos y la contención
data/         Dataset, capturas y modelos — NO se versiona (~880 MB)
```

`data/`, los archivos `.pcap` y los modelos serializados están en `.gitignore`. El
dataset CICIDS2017 debe descargarse aparte y colocarse en `data/raw/`.

Cada etapa del trabajo deja un informe reproducible en `scripts/scripts_output/`, y la
decisión escrita correspondiente en `contract/A*_note.md`.

---

## Puesta en marcha

### Requisitos

- **Python 3.12 o superior.** `cicflowmeter 0.5.0` lo exige; con 3.11 la instalación
  falla sin mencionar la causa.
- `libpcap` y `tcpdump`, que `scapy` necesita para leer archivos `.pcap`.
  Debian/Ubuntu: `apt install libpcap0.8 tcpdump` · Fedora: `dnf install libpcap tcpdump`.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Las versiones están fijadas, `cicflowmeter 0.5.0` incluida: el comportamiento descrito
en los informes y las correcciones aplicadas dependen de esa versión exacta.

### Verificar que la herramienta de medición mide bien

Antes de entrenar nada. Estas órdenes reconstruyen la evidencia versionada desde cero:

```bash
python scripts/check_cicflowmeter.py          # captura sintética de verdad conocida
python src/intelligence/pcap_to_csv.py \
    data/pcap/synthetic_smoke.pcap \
    data/pcap/smoke_flows.csv
diff data/pcap/smoke_flows.csv contract/smoke_flows.csv   # salvo la marca de tiempo
```

La captura sintética se construye en memoria y se escribe a disco. **En ningún momento
se transmite tráfico por una red real**, y las direcciones utilizadas son ficticias.

### Pruebas

```bash
pytest -v
```

Las pruebas no comprueban «si el código se ejecuta»: cada una corresponde a una forma
concreta en que las dos mitades del sistema podrían separarse en silencio, y su
docstring explica qué se rompería si fallara.

---

## Uso

### Entrenamiento

Cada etapa acepta `--help`, escribe su informe en `scripts/scripts_output/` y puede
ejecutarse por separado:

```bash
python src/intelligence/preprocess.py     # A3  data/raw → data/processed
python src/intelligence/train.py          # A4  ajusta los tres clasificadores → models/
python src/intelligence/evaluate.py       # A5  compara y elige
python src/intelligence/threshold.py      # A6  fija el punto de operación
python src/intelligence/recalibrate.py    # A7  recalibra contra tráfico del laboratorio
```

### Operación

```bash
# Detección en vivo: PacketCapture ensambla flujos, puntúa y alimenta el SOAR
python -c "from src.system.capture import PacketCapture; PacketCapture().start()"

# Panel de casos, severidades y bloqueos
streamlit run src/system/panel.py

# Reproducir una captura guardada en lugar de escuchar la interfaz
python tests/replay_pcap.py <archivo.pcap>
```

La interfaz de captura, el filtro BPF y el resto de parámetros se leen de
[`src/common/config.py`](src/common/config.py).

---

## El laboratorio

Red aislada, sin salida a Internet:

```
VM-ATACANTE                         VM-VÍCTIMA
192.168.56.20                       192.168.56.10
Kali Linux                          Fedora 44
nmap / hping3 / hydra               IDS + SOAR
       \                              /
        +------ 192.168.56.0/24 ------+
                   vboxnet0
```

El tráfico de ataque se genera exclusivamente contra la máquina víctima del propio
laboratorio, que es una VM controlada por el equipo y recuperable mediante snapshot.

### Cómo decide el SOAR

La severidad es **probabilidad y contexto, nunca probabilidad sola**. Un flujo de
confianza media es LOW; la misma IP produciendo varios es MEDIUM; una ráfaga sostenida
es HIGH. Eso es lo que permite que un escaneo lento —88 flujos alrededor de 0,57, ninguno
individualmente por encima de la banda alta— llegue igualmente a severidad HIGH.

A esto se suma la correlación por tasa, medida sobre tráfico real del laboratorio: el
tráfico benigno alcanza como máximo 300 conexiones nuevas por IP cada 10 segundos, y
slowloris llega a 486, de modo que el umbral se fija en 400, con margen a ambos lados.
Los puertos de autenticación tienen una regla mucho más estricta: el tráfico benigno del
laboratorio tiene **cero** conexiones al puerto 22, y un inicio de sesión real es una
conexión, así que diez en un minuto no pueden ser una persona.

### Precauciones de contención

- **Lista blanca.** La puerta de enlace y la propia víctima nunca se bloquean. Sin ella,
  una regla del IDS puede dejar la máquina incomunicada.
- **Modo de operación.** `MODE` admite `monitor`, `alert` y `enforce`. Solo el último
  escribe reglas de firewall, y puede cambiarse en caliente desde el panel.
- **Expiración en el kernel.** El tiempo de vida del bloqueo vive en el `ipset`, no en un
  temporizador de Python: si el proceso del IDS muere, el kernel expira el bloqueo de
  todos modos. **No existe el bloqueo automático permanente.**
- **Privilegios acotados.** En lugar de ejecutar el IDS entero como root, el usuario
  recibe una regla de `sudoers` limitada a `iptables` e `ipset`.
- **Ensayo en seco.** `CONTAINMENT_DRY_RUN` hace que la contención imprima las órdenes
  que ejecutaría, para desarrollar fuera de la VM sin tocar ningún firewall.

`src/system/containment.py` es el único módulo del sistema que toca el firewall. Nada por
encima de él sabe que `iptables` existe.

---

## Documentación

| Documento | Contenido |
|---|---|
| `contract/contract_characteristics.md` | El contrato: las 24 características, su selección y las reglas R1–R4 |
| `contract/A1`…`A7_*.md` | Bitácora de decisiones: análisis, validación de paridad, preprocesamiento, entrenamiento, evaluación, umbral y recalibración |
| `copilot/cicflowmeter_bugs.md` | Los tres defectos de la herramienta y la divergencia R2 |
| `copilot/B0`…`B2_*.md` | Montaje del laboratorio, captura de tráfico, `Flow` y `FlowManager` |
| `scripts/scripts_output/` | Salida reproducible de cada auditoría e informe |

---

## Ramas

| Rama | Responsable | Alcance |
|---|---|---|
| `ia-model` | Sebastián (persona A) | Dataset, contrato, extractor, entrenamiento y modelo |
| `soar-response` | Frank (persona B) | Captura en vivo, ensamblado de flujos, motor SOAR, contención y panel |
| `main` | — | Integración |

---

## Equipo

- **Sebastián Chávez** — inteligencia y datos: dataset, contrato de características,
  extractor y modelo.
- **Frank** — sistema: captura en vivo, motor SOAR, contención con `iptables` y panel.

Convención del proyecto: el código, los nombres de archivo, las variables y los
comentarios en **inglés**; la documentación de `contract/` y `copilot/` en **español**,
en registro técnico formal.

---

## Licencia

MIT. Véase [`LICENSE`](LICENSE).
