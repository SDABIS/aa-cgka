import pandas as pd
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression
from sklearn.metrics import r2_score
import numpy as np

x_label = "epoch"

def compare_r2_score(x, y):
    # Linear
    X = x.reshape(-1, 1)
    linear_model = LinearRegression()
    linear_model.fit(X, y)
    
    # Log
    X_log = np.log(x + 1).reshape(-1, 1)
    log_model = LinearRegression()
    log_model.fit(X_log, y)

    # Predict and score
    y_pred_linear = linear_model.predict(X)
    y_pred_log = log_model.predict(X_log)
    r2_linear = r2_score(y, y_pred_linear)
    r2_log = r2_score(y, y_pred_log)

    print(operation, line_names[i], r2_linear, r2_log)

def group_and_average(df):
    df = df.sort_values(by=x_label)  
    df = df[df[x_label] < 250]
    df[x_label] = (df[x_label] // 20) * 20
    return df.groupby(['group', x_label]).agg({
        'gen_elapsed_mean': 'mean',
        'processing_elapsed_mean': 'mean',
        'sizes_mean': 'mean',
        'kp_sizes': 'mean',
        'kp_elapsed': 'mean',
        'welcome_times': 'mean',
        'welcome_size': 'mean',
        'join_size': 'mean'
    }).reset_index()

folder_path = "."

#operations = ['gen_elapsed_mean', "processing_elapsed_mean", "sizes_mean"]
#y_labels = ['Generation time (microseconds)', 'Processing time (microseconds)', 'Size per update (Bytes)']

#line_names = ["Commit", "1 Prop", "2 Prop", "4 Prop", "8 Prop"]
#files = ['grouped_logs_commit.csv', "grouped_logs_prop_1.csv", 'grouped_logs_prop_2.csv', "grouped_logs_prop_4.csv", "grouped_logs_prop_8.csv"]

#line_names = ["First", "Random", "Last"]
#files = ['grouped_logs_FIRST.csv', "grouped_logs_RANDOM.csv", "grouped_logs_LAST.csv"]

operations = ['gen_elapsed_mean', 'processing_elapsed_mean', 'sizes_mean']
y_labels = ['Generation time (microseconds)', 'Processing time (microseconds)', 'Size per update (Bytes)']
line_names = ["Basic (Add)", "Basic (Join)", "SDJWT (Add)", "SDJWT (Join)", "BBS (Add)", "BBS (Join)"]
files = ['grouped_logs_basic_add.csv', 'grouped_logs_basic_join.csv', 'grouped_logs_sdjwt_add.csv', 'grouped_logs_sdjwt_join.csv', 'grouped_logs_bbs_add.csv', 'grouped_logs_bbs_join.csv']
colors = ['blue', 'green', 'red']

all_lines = []
for operation, y_label in zip(operations, y_labels):
    operation_lines = []
    plt.figure(figsize=(8, 6))

    for i in range(len(files)):
        # Load CSV
        file_path = folder_path + "/" + files[i]
        data = pd.read_csv(file_path)

        data = group_and_average(data)
        #data = data[data[x_label] < 750]

        data[x_label] = pd.to_numeric(data[x_label], errors='coerce')
        data[operation] = pd.to_numeric(data[operation], errors='coerce')
        data[x_label] = data[x_label].fillna(0).astype(int)

        #compare_r2_score(data[x_label].values, data[operation].sort_values)

        operation_lines.append(data[operation])

        color = colors[i // 2] 
        linestyle = '-' if i % 2 == 0 else '--'

        plt.plot(data[x_label], data[operation], label=line_names[i], linestyle=linestyle, color=color)

    plt.xlabel('Users')
    plt.ylabel(y_label)
    # use extended notation for y axis instead of scientific notation

    #plt.yscale("log")
    #plt.title('Mean message size')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(operation + ".pdf")
    plt.show()

    all_lines.append(operation_lines)


print("\n")

for i in range(len(operations)):
    for j in range(len(line_names)):
        first_op = operations[i]

        second_op_index = (i+1) % len(operations)
        second_op = operations[second_op_index]

        line_name = line_names[j]
        first_data = all_lines[i][j]
        second_data = all_lines[second_op_index][j]

        corr = np.corrcoef(first_data, second_data)[0][1]

        print(f"{first_op} - {second_op} ({line_name}): {corr}")