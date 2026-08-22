import pandas as pd, glob

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 200)

FLAGS = ["FIN Flag Count", "SYN Flag Count", "RST Flag Count",
         "PSH Flag Count", "ACK Flag Count"]

frames = []
for path in sorted(glob.glob("data/raw/*.csv")):
    df = pd.read_csv(path, nrows=200_000, low_memory=False)
    df.columns = df.columns.str.strip()
    frames.append(df[FLAGS + ["Label"]])

todo = pd.concat(frames, ignore_index=True)

print("Máximo global por bandera:")
print(todo[FLAGS].max())          # si todos son 1 -> booleanas, confirmado
print("\nMedia por etiqueta (dataset completo):")
print(todo.groupby("Label")[FLAGS].mean().round(3))