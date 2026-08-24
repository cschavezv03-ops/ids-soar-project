# Informe técnico — Detección y corrección de dos defectos en `cicflowmeter 0.5.0`

**Proyecto:** Sistema de Detección de Intrusiones de Red con Respuesta Automática SOAR
**Curso:** Fundamentos de Inteligencia Artificial · Summer Camp 2026 · CyberMinds EPN
**Autor:** Sebastián (componente de inteligencia y datos)
**Fase del proyecto:** preparación del entorno, previa al entrenamiento del modelo

---

## Resumen ejecutivo

Durante la validación inicial del entorno se detectaron **dos defectos en la librería
`cicflowmeter 0.5.0`**, la herramienta encargada de convertir tráfico de red en las
características numéricas que alimentan el modelo de aprendizaje automático.

El primero impide ejecutar la herramienta desde la línea de comandos: falla de forma visible
en cualquier invocación. El segundo es más grave precisamente porque **no falla**: la
herramienta termina correctamente y produce un archivo bien formado con valores incorrectos,
al contabilizar dos veces el primer paquete de cada conversación de red.

Ambos defectos se corrigieron sin modificar la librería. La corrección se verificó
numéricamente contra un caso de prueba de respuesta conocida, con coincidencia exacta en todas
las magnitudes comprobadas.

---

## 1. Contexto: qué hace la herramienta y por qué su exactitud es crítica

El sistema clasifica tráfico de red como legítimo o malicioso. El modelo de aprendizaje
automático no analiza paquetes directamente: analiza **flujos**, es decir, conversaciones
completas entre dos máquinas, descritas mediante un vector de características numéricas
(duración, número de paquetes y bytes en cada sentido, tamaños, ritmo temporal, recuento de
banderas del protocolo TCP, simetría de la conversación).

`cicflowmeter` es la herramienta que realiza esa conversión. Ocupa una posición particular en
la arquitectura del sistema, porque interviene en **dos momentos distintos**:

| Momento | Entrada | Uso |
|---|---|---|
| Entrenamiento | Dataset público CICIDS2017 | El modelo aprende a partir de estas características |
| Operación en vivo | Tráfico capturado en tiempo real | El modelo clasifica a partir de estas características |

Para que el sistema funcione, ambos caminos deben producir **el mismo número para la misma
característica**. Esta propiedad se denomina *paridad*, y se garantiza usando la misma
herramienta en los dos lados.

De ahí la consecuencia que motiva este informe: **si la herramienta calcula mal, el modelo
aprende sobre una realidad y decide sobre otra**. Las métricas de evaluación saldrían
excelentes y el sistema fallaría al desplegarse. Por ese motivo la herramienta se validó
antes de utilizarla, y no después.

---

## 2. Método de verificación

Verificar una herramienta de medición exige contrastarla contra una **verdad conocida**. Para
ello se construyó un archivo de captura sintético (formato `pcap`) cuyo contenido se conoce
con exactitud, porque fue generado deliberadamente para la prueba:

| Conversación | Contenido | Paquetes |
|---|---|---|
| `10.0.0.5:54321 → 10.0.0.10:80` | Sesión TCP completa: apertura en tres pasos, intercambio de datos en ambos sentidos y cierre ordenado | 4 de ida + 3 de vuelta = 7 |
| `10.0.0.5:40000 → 10.0.0.10:22` | Sonda de exploración de puertos: solicitud de conexión, rechazo | 2 |
| `10.0.0.5:40001 → 10.0.0.10:443` | Sonda de exploración de puertos | 2 |
| `10.0.0.5:40002 → 10.0.0.10:3306` | Sonda de exploración de puertos | 2 |
| **Total** | | **13 paquetes** |

Se eligieron dos formas de tráfico opuestas —una conversación completa y varias sondas de
exploración— porque entre ambas ejercitan todos los grupos de características que el modelo
utiliza: volumen, tamaños, ritmo temporal, banderas del protocolo y simetría.

Los paquetes se construyeron en memoria y se escribieron a disco. **En ningún momento se
transmitió tráfico por una red real.** Las direcciones utilizadas son ficticias.

Disponer de esta verdad conocida es lo que permitió detectar el segundo defecto. Sin ella, el
resultado producido por la herramienta habría parecido plenamente razonable.

---

## 3. Defecto 1 — La interfaz de línea de comandos no funciona

### Manifestación

Toda invocación desde la terminal termina en error:

```
$ cicflowmeter -f entrada.pcap -c salida.csv
...
File ".../cicflowmeter/sniffer.py", line 40, in create_sniffer
    fields = fields.split(",")
AttributeError: 'bool' object has no attribute 'split'
```

El mensaje indica que una variable llamada `fields`, que el código espera que contenga texto,
contiene en realidad un valor lógico (verdadero/falso).

### Causa

La función interna `create_sniffer()` declara siete parámetros en este orden:

```python
def create_sniffer(
    input_file, input_interface, output_mode, output,
    input_directory=None, fields=None, verbose=False
):
```

La función que atiende la línea de comandos la invoca pasando los valores **por posición**, sin
indicar a qué parámetro corresponde cada uno:

```python
create_sniffer(
    args.input_file,
    args.input_interface,
    args.output_mode,
    args.output,
    args.fields,
    args.verbose,
)
```

Cuando los argumentos se pasan por posición, el lenguaje los asigna por orden de aparición. La
asignación resultante es la siguiente:

| Posición | Valor enviado | Parámetro que lo recibe | Correcto |
|---|---|---|---|
| 1 | `input_file` | `input_file` | Sí |
| 2 | `input_interface` | `input_interface` | Sí |
| 3 | `output_mode` | `output_mode` | Sí |
| 4 | `output` | `output` | Sí |
| 5 | `fields` | **`input_directory`** | **No** |
| 6 | `verbose` | **`fields`** | **No** |
| — | (ninguno) | `verbose` | **No** |

En una revisión anterior de la librería se insertó el parámetro `input_directory` en mitad de la
declaración, sin actualizar esta llamada. Todos los valores posteriores quedaron desplazados una
posición.

El fallo se produce tres líneas más abajo:

```python
if fields is not None:            # contiene un valor lógico, que no es "nulo"
    fields = fields.split(",")    # intenta tratarlo como texto → error
```

### Por qué el defecto es inevitable

El parámetro `verbose` contiene siempre un valor lógico —verdadero o falso—, nunca un valor
nulo. Como siempre acaba asignado a `fields`, la condición se cumple invariablemente y el error
se produce en todos los casos. No existe combinación de opciones de línea de comandos que
permita evitarlo.

### Corrección aplicada

Se evita la función de línea de comandos y se invoca directamente la función interna
**nombrando cada argumento**. Al hacerlo, cada valor se asigna explícitamente a su parámetro y
el desplazamiento deja de ser posible:

```python
create_sniffer(
    input_file=str(pcap_path),
    input_interface=None,
    output_mode="csv",
    output=str(csv_path),
    input_directory=None,
    fields=None,
    verbose=False,
)
```

El motor de cálculo de la librería no está implicado en este defecto: el fallo se produce en la
capa que interpreta las opciones de la terminal, antes de que el procesamiento comience.

---

## 4. Defecto 2 — Doble contabilización del primer paquete de cada flujo

Este defecto es cualitativamente distinto del anterior. **No produce ningún mensaje de error.**
El programa se ejecuta hasta el final, genera un archivo correctamente formado, y los valores
que contiene son incorrectos.

### Detección

Al procesar el archivo de prueba de 13 paquetes, la herramienta informó de 17:

| Flujo | Paquetes reales | Paquetes informados |
|---|---|---|
| Conversación completa | 4 ida + 3 vuelta = **7** | 5 ida + 3 vuelta = **8** |
| Sonda hacia el puerto 22 | **2** | **3** |
| Sonda hacia el puerto 443 | **2** | **3** |
| Sonda hacia el puerto 3306 | **2** | **3** |
| **Total** | **13** | **17** |

Cada flujo informa de **exactamente un paquete de más en el sentido de ida**. El volumen de
datos lo confirma: la herramienta reportó 288 bytes en ese sentido cuando la suma real es 234.
La diferencia, 54 bytes, coincide exactamente con el tamaño del primer paquete de la
conversación.

### Causa

El defecto reside en la interacción de dos fragmentos situados en archivos distintos. El
constructor de la clase que representa un flujo ya almacena el primer paquete:

```python
class Flow:
    def __init__(self, packet, direction):
        ...
        self.packets = [(packet, direction)]   # el paquete queda registrado aquí
```

Y la función que procesa el tráfico, inmediatamente después de construir el flujo, vuelve a
registrarlo:

```python
if flow is None:
    flow = Flow(pkt, direction)
    ...
flow.add_packet(pkt, direction)                # el mismo paquete se registra otra vez
```

El resultado es que el primer paquete de cada conversación queda contabilizado dos veces.

### Magnitudes afectadas

El defecto no es cosmético. Distorsiona características que el modelo utiliza para clasificar:

| Distorsionadas | No afectadas |
|---|---|
| Número total de paquetes y de bytes en el sentido de ida | Todas las magnitudes del sentido de vuelta |
| Tamaño medio y desviación de los paquetes | Recuento de banderas ACK, FIN, RST y PSH |
| **Recuento de banderas SYN** | Duración del flujo |
| Tasas de paquetes y de bytes por segundo | |
| **Estadísticas de tiempo entre paquetes** | |
| Relación de simetría entre ambos sentidos | |

Dos de ellas merecen mención específica por su papel en la detección de ataques:

**Recuento de banderas SYN.** El primer paquete de toda conexión TCP lleva activada la bandera
SYN, que señala el inicio de la conexión. Al duplicarse, se introduce sistemáticamente un SYN
inexistente. Este recuento es una de las señales más discriminantes para identificar
exploraciones de puertos e inundaciones de peticiones de conexión.

**Estadísticas de tiempo entre paquetes.** El paquete duplicado conserva la marca temporal del
original, de modo que el intervalo entre ambos es cero. Esto inyecta un valor nulo artificial en
las medidas de ritmo temporal, que son precisamente las que permiten detectar exploraciones
deliberadamente lentas, diseñadas para no superar ningún umbral por unidad de tiempo.

### Por qué este defecto era el peligroso

Un modelo entrenado con el dataset público y alimentado en operación con valores afectados por
este defecto recibiría datos **sistemáticamente distintos** de aquellos con los que aprendió.
Las métricas de evaluación resultarían satisfactorias y el sistema fallaría al desplegarse, sin
ningún indicio que permitiera relacionar el fallo con su causa.

### Corrección aplicada

Se sustituye en tiempo de ejecución el constructor de la clase por una versión que vacía el
registro de paquetes después de inicializarlo. La función de procesamiento vuelve a añadir el
paquete inmediatamente después, de modo que no se pierde información: simplemente deja de
registrarse dos veces.

```python
from cicflowmeter.flow import Flow

_original_flow_init = Flow.__init__


def _patched_flow_init(self, packet, direction):
    _original_flow_init(self, packet, direction)
    # Drop the pre-seeded packet. The processing function adds it back
    # immediately after construction, so no information is lost.
    self.packets = []


Flow.__init__ = _patched_flow_init
```

La sustitución se aplica al cargar el módulo del proyecto, antes de que se construya ningún
flujo. La librería no se modifica en disco: la corrección reside en el código del proyecto, de
modo que forma parte del repositorio y se aplica de forma idéntica en cualquier máquina donde el
sistema se instale.

---

## 5. Verificación de la corrección

Se reprocesó el mismo archivo de prueba y se contrastó cada magnitud contra la verdad conocida:

| Magnitud | Antes | Después | Valor real |
|---|---|---|---|
| Paquetes contabilizados (total) | 17 | **13** | 13 |
| Paquetes ida / vuelta (conversación) | 5 / 3 | **4 / 3** | 4 / 3 |
| Bytes en sentido de ida | 288 | **234** | 234 |
| Recuento de banderas SYN | 3 | **2** | 2 |
| Tiempo mínimo entre paquetes | 0,00 | **0,01** | 0,01 |
| Relación de simetría | 0,60 | **0,75** | 0,75 |
| Paquetes de ida (sonda) | 2 | **1** | 1 |

**Coincidencia exacta en todas las magnitudes comprobadas.**

---

## 6. Reproducibilidad

La verificación puede repetirse íntegramente con tres órdenes:

```bash
source .venv/bin/activate

# 1. Generar el archivo de captura sintético de verdad conocida (13 paquetes)
python scripts/check_cicflowmeter.py

# 2. Extraer los flujos con el módulo corregido
python src/intelligence/pcap_to_csv.py \
    data/pcap/synthetic_smoke.pcap \
    data/pcap/smoke_flows.csv

# 3. Contrastar contra la verdad conocida
python -c "
import pandas as pd
df = pd.read_csv('data/pcap/smoke_flows.csv')
print(df[['tot_fwd_pkts','tot_bwd_pkts','totlen_fwd_pkts',
          'syn_flag_cnt','flow_iat_min','down_up_ratio']].to_string())
"
```

Resultado esperado — primera fila: `4  3  234  2  0.01  0.75`. Filas restantes:
`1  1  54  1  0.00  1.00`.

La versión de la librería queda fijada en `requirements.txt`, de modo que el comportamiento
descrito y las correcciones aplicadas son reproducibles en cualquier instalación del sistema.

---

## 7. Conclusión

Los dos defectos ilustran una asimetría relevante en el desarrollo de sistemas que dependen de
mediciones.

El primero interrumpe la ejecución con un mensaje de error explícito. Resulta imposible de
ignorar y, por tanto, se corrige de inmediato: su coste real es bajo.

El segundo no produce ninguna señal. La herramienta se ejecuta con normalidad y entrega
resultados incorrectos. Un defecto de esta naturaleza puede propagarse a través de todo el
proceso —entrenamiento, evaluación, informe de métricas— sin manifestarse hasta el despliegue,
momento en el que resulta difícil relacionar el fallo con su origen.

La única defensa frente a un defecto silencioso consiste en contrastar la herramienta contra un
caso cuya respuesta se conoce de antemano. Ese principio motivó la construcción del archivo de
prueba sintético y justifica la decisión de validar la herramienta antes de utilizarla, y no
después de haber entrenado un modelo con ella.
