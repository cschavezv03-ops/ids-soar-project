# Nota de validación A2 — Paridad del extractor

**Tarea:** A2, construir el extractor y validar la paridad.
**Criterio de salida (fase 0):** el mismo tráfico da los mismos valores por las
dos vías. Alcanzado.
**Contrato:** v1.0, sin cambios. Ninguna característica hubo que sustituir.

---

## 1. Qué se validó y con qué evidencia

La paridad se descompone en dos preguntas distintas, y cada una se comprobó con
un instrumento distinto.

### Paridad B — el extractor contra el espacio de valores del CSV

Es la que cierra la fase 0: ¿nuestros 24 números viven en el mismo espacio
numérico que los de CICIDS2017? No se puede comprobar flujo a flujo contra el
dataset (harían falta las capturas crudas de 2017, que no existen), así que se
comprueba contra **verdad conocida**: el pcap sintético de A0, cuyo tráfico se
construyó paquete a paquete y cuyas 24 características se derivaron a mano,
independientemente de la herramienta.

- **Instrumento:** `scripts/parity_bench.py`
- **Evidencia:** `scripts/scripts_output/parity_bench.txt`
- **Resultado:** 24/24 características coinciden con la verdad calculada a mano,
  sobre los 4 flujos del pcap sintético (96 comparaciones). Criterios por grupo:
  `COUNT_IDX` exacto sin tolerancia, `TIME_IDX` con tolerancia tras R1,
  `PAYLOAD_IDX` contra los valores a mano, resto con tolerancia relativa 1e-6.

La tabla de verdad codifica los tres arreglos de la herramienta funcionando:
R1 (tiempo en microsegundos), R2 (longitud como payload, flujos de escaneo a 0),
y el defecto 3 (un solo intervalo IAT informa el valor real, no cero).

### Paridad A — el extractor consigo mismo sobre tráfico real

¿El extractor produce vectores válidos sobre tráfico real, no solo sintético?
No hay verdad numérica conocida para el tráfico real, así que aquí no se validan
valores exactos, sino robustez y forma.

- **Instrumento:** `scripts/profile_pcap.py`
- **Evidencia:** `scripts/scripts_output/profile_pcap.txt`
- **Resultado:** sobre los 7 pcaps del laboratorio (más de 2.500 flujos reales,
  incluidos 1.147 del escaneo rápido), **cero flujos inválidos**: ninguna
  longitud distinta de 24, ningún valor no finito o negativo, ningún fallo de
  `validate()`. La forma de cada captura coincide con su etiqueta (escaneo y
  flood: flujos minúsculos de control; benignos: flujos mayores con payload).

---

## 2. Las tres reglas de normalización, verificadas

| Regla | Qué hace | Dónde vive | Verificada por |
|---|---|---|---|
| R1 | segundos → microsegundos (7 posiciones de tiempo) | `contract.seconds_to_contract_time`, aplicada en el extractor | banco: `flow_duration` 0,06 s → 60000 µs |
| R2 | longitud de paquete = payload, con relleno Ethernet | medición, en `cicflowmeter_patches.py` | banco: escaneo a 0; auditoría de dataset (99,26 % de PortScan) |
| R3 | inf/NaN → 0.0, todo a float | `contract.sanitize`, aplicada en el extractor | tests de extractor: inf/NaN de flujos de duración cero |

---

## 3. Defectos de la herramienta corregidos en el camino

Documentados en `copilot/cicflowmeter_bugs.md`:

1. Crash de CLI por argumentos posicionales.
2. Doble conteo del primer paquete de cada flujo.
3. Estadísticos IAT de un flujo de dos paquetes colapsaban a cero. Verificado
   contra 993.104 flujos del dataset que el Java mide bien: se parchea.

Y una divergencia de definición (no un defecto): la longitud de paquete se mide
como payload con relleno Ethernet, replicando el CSV.

---

## 4. Cobertura de pruebas

- `tests/test_contract.py` — 26 pruebas del contrato.
- `tests/test_patches.py` — 19 pruebas de los parches y R2.
- `tests/test_extractor.py` — 13 pruebas de `extract_features`.
- Total: 58 pruebas en verde.
- `scripts/parity_bench.py` — 24/24, código de salida 0 (usable en CI).

---

## 5. Preguntas abiertas para tareas posteriores

Ninguna bloquea A2. Se registran para no perderlas.

- **Relleno Ethernet asimétrico (resuelto).** Las primeras capturas de Frank no
  rellenaban el tráfico saliente; habría dado 0 en vivo donde el CSV da 6, en
  las posiciones 9-12. Frank lo normalizó en la captura; verificado con
  `check_lab_padding.py`. Sin compensación en el extractor.
- **0,52 % de flujos de dos paquetes** no cumplen la identidad IAT = duración
  por más de 1 µs. No son ceros, no afectan a la paridad. Origen sin estudiar.
- **Para A7 (calibración con tráfico propio):** las capturas benignas del
  laboratorio son flujos únicos y largos (un SSH = 1 flujo = 1 ejemplo), no
  cientos. El SYN flood tiene 3 paquetes por flujo, no 2. Habrá que definir qué
  capturas pedir a Frank en función de cómo se calibre el umbral — decisión de
  A7, no de A2.
