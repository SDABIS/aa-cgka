import pandas as pd
import matplotlib.pyplot as plt

x_label = "epoch"

def group_and_average(df):
    df = df.sort_values(by=x_label)
    df[x_label] = (df[x_label] // 20) * 20
    return df.groupby(['group', x_label]).agg({
        'mean_latency': 'mean',
        'max_latency': 'mean',
    }).reset_index()

# Load CSV
folder_path = "."
file_name = 'grouped_logs.csv'

file_path = folder_path + "/" + file_name
data = pd.read_csv(file_path)

data = group_and_average(data)

data[x_label] = pd.to_numeric(data[x_label], errors='coerce')
data['mean_latency'] = pd.to_numeric(data['mean_latency'], errors='coerce')
data['max_latency'] = pd.to_numeric(data['max_latency'], errors='coerce')
data[x_label] = data[x_label].fillna(0).astype(int)

# Create plot
plt.figure(figsize=(8, 6))
plt.plot(data[x_label], data['mean_latency'], label='Mean Latency', color='blue', marker='o')
plt.plot(data[x_label], data['max_latency'], label='Max Latency', color='red', marker='o')

plt.ticklabel_format(style='plain', axis='y')
plt.xlabel('Users')
plt.ylabel('Latency (Microseconds)')
#plt.title('Mean and Max Latency')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig("latency_plot.jpg")

plt.show()