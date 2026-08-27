import pandas as pd

df = pd.read_csv("data/raw/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", nrows=200_000)
df.columns = df.columns.str.strip()          # el fix de los espacios

scan = df[df["Label"] == "PortScan"]
print(scan[["Flow Duration", "Total Length of Fwd Packets",
            "Fwd Packet Length Max", "Down/Up Ratio",
            "SYN Flag Count"]].describe())