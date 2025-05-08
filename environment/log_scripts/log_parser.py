import pandas as pd
import glob
import os
import ast
pd.options.display.max_columns = None


log_directory = '../client/logs'

transforms = ["outliers", "remove_last"]
log_files = glob.glob(os.path.join(log_directory, '*.txt'))

data_frames = []

# Function that reads a log file and classifies all its lines
def read_log_file(file):
    data = []
    with open(file, 'r') as f:
        for line in f:
            parts = line.split()

            # 4th element determines the operation
            operation = parts[3]

            # Each operation is composed of different values
            if operation in ['Create']:
                group, epoch, user_id, operation, timestamp, elapsed = parts
                target_user_id = None
                size = 0
                other_size = 0
                number_of_proposals = 1
            elif operation in ['Commit']:
                group, epoch, user_id, operation, number_of_proposals, size, timestamp, elapsed = parts
                other_size = 0
                target_user_id = None
            elif operation in ['Update']:  
                group, epoch, user_id, operation, size, timestamp, elapsed = parts
                target_user_id = None
                other_size = 0
                number_of_proposals = 1
            elif operation in ['Join']:
                group, epoch, user_id, operation, size, other_size, timestamp, elapsed = parts
                target_user_id = None
                number_of_proposals = 1
            elif operation in ['Invite', 'Remove']:
                group, epoch, user_id, operation, target_user_id, size, timestamp, elapsed = parts
                other_size = 0
                number_of_proposals = 1
            elif operation in ['Process', 'StoreProp']:
                group, epoch, user_id, operation, target_user_id, timestamp, elapsed = parts
                other_size = 0
                size = 0
                number_of_proposals = 0
            elif operation in ['Welcome']:
                group, epoch, user_id, operation, target_user_id, other_size, timestamp, elapsed = parts
                size = 0
                number_of_proposals = 0
            elif operation in ['GenKP']:
                group, epoch, user_id, operation, size, other_size, timestamp, elapsed = parts
                target_user_id = None
                number_of_proposals = 0
            elif operation in ['Propose']:
                sub_operation = parts[4]
                if sub_operation in ['Invite', 'Remove']:
                    group, epoch, user_id, operation, sub_operation, target_user_id, size, timestamp, elapsed = parts
                    other_size = 0
                    number_of_proposals = 0

                elif sub_operation in ['Update']:
                    group, epoch, user_id, operation, sub_operation, size, timestamp, elapsed = parts
                    other_size = 0
                    number_of_proposals = 0

            else:
                continue
            
            # add new line to dataframe
            data.append([group, int(epoch), user_id, operation, target_user_id, int(size), int(other_size), int(number_of_proposals), int(timestamp), int(elapsed)])
    
    # create dataframe with all lines
    df = pd.DataFrame(data, columns=["group", "epoch", "user_id", "operation", "target_user_id", "size", "other_size", "number_of_proposals", "timestamp", "elapsed_time"])
    return df

# Parse all log files into a dataframe
for file in log_files:
    df = read_log_file(file)
    data_frames.append(df)

# Concatenate all dataframes
all_logs_df = pd.concat(data_frames, ignore_index=True)

# Separate the lines that create new epochs
epoch_generating_events = all_logs_df[all_logs_df['operation'].isin(['Commit', 'Update', 'Remove', 'Join', 'Create', 'Invite'])]
propose_events = all_logs_df[all_logs_df['operation'].isin(['Propose'])]
process_events = all_logs_df[all_logs_df['operation'].isin(['Process'])]
welcome_events = all_logs_df[all_logs_df['operation'].isin(['Welcome'])]
process_proposals_events = all_logs_df[all_logs_df['operation'].isin(['StoreProp'])]
gen_kp_events = all_logs_df[all_logs_df['operation'].isin(['GenKP'])]

# Group logs by group and epoch and rename columns
# Should only be 1 for group and epoch
epoch_generating_events_grouped = epoch_generating_events.groupby(['group', 'epoch']).agg({
    'timestamp': 'min',
    'size': 'first',
    'elapsed_time': 'first',
    'other_size': 'max',
    'number_of_proposals': 'max'
}).reset_index()
epoch_generating_events_grouped.rename(columns={'timestamp': 'epoch_generating_timestamp'}, inplace=True)
epoch_generating_events_grouped.rename(columns={'other_size': 'join_size'}, inplace=True)
epoch_generating_events_grouped.rename(columns={'elapsed_time': 'gen_time'}, inplace=True)

propose_events_grouped = propose_events.groupby(['group', 'epoch']).agg({
    'size': 'mean',
    'elapsed_time': 'mean',
}).reset_index()
propose_events_grouped.rename(columns={'size': 'propose_sizes'}, inplace=True)
propose_events_grouped.rename(columns={'elapsed_time': 'propose_times'}, inplace=True)

process_events_grouped = process_events.groupby(['group', 'epoch']).agg({
    'timestamp': list,
    'elapsed_time': 'mean',
}).reset_index()
process_events_grouped.rename(columns={'timestamp': 'other_timestamps'}, inplace=True)
process_events_grouped.rename(columns={'elapsed_time': 'process_times'}, inplace=True)

welcome_events_grouped = welcome_events.groupby(['group', 'epoch']).agg({
    'timestamp': list,
    'elapsed_time': 'mean',
    'other_size': 'mean',
}).reset_index()
welcome_events_grouped.rename(columns={'timestamp': 'welcome_timestamps'}, inplace=True)
welcome_events_grouped.rename(columns={'other_size': 'welcome_size'}, inplace=True)
welcome_events_grouped.rename(columns={'elapsed_time': 'welcome_times'}, inplace=True)

process_proposals_events_grouped = process_proposals_events.groupby(['group', 'epoch']).agg({
    'elapsed_time': 'mean',
}).reset_index()
process_proposals_events_grouped.rename(columns={'elapsed_time': 'storeprop_times'}, inplace=True)

gen_kp_events_grouped = gen_kp_events.groupby(['group', 'epoch']).agg({
    'elapsed_time': 'mean',
    'size': 'mean',
    'other_size': 'mean'
}).reset_index()
gen_kp_events_grouped.rename(columns={'size': 'kp_sizes'}, inplace=True)
gen_kp_events_grouped.rename(columns={'elapsed_time': 'kp_elapsed'}, inplace=True)
gen_kp_events_grouped.rename(columns={'other_size': 'join_size'}, inplace=True)

#count number of users per epoch
user_counts = process_events.groupby(['group', 'epoch']).size().reset_index(name='num_users')
user_counts['num_users'] = user_counts['num_users'].astype(int)

# Combine all dataframes
grouped_logs = pd.merge(epoch_generating_events_grouped, propose_events_grouped, on=['group', 'epoch'], how='outer')
grouped_logs = pd.merge(grouped_logs, process_events_grouped, on=['group', 'epoch'], how='outer')
grouped_logs = pd.merge(grouped_logs, process_proposals_events_grouped, on=['group', 'epoch'], how='outer')
grouped_logs = pd.merge(grouped_logs, welcome_events_grouped, on=['group', 'epoch'], how='outer')
grouped_logs = pd.merge(grouped_logs, gen_kp_events_grouped, on=['group', 'epoch'], how='outer')
grouped_logs = pd.merge(grouped_logs, user_counts, on=['group', 'epoch'], how='outer')

grouped_logs['join_size'] = grouped_logs[['join_size_x', 'join_size_y']].mean(axis=1, skipna=True)
grouped_logs.drop(columns=['join_size_x', 'join_size_y'], inplace=True)

grouped_logs['number_of_proposals'] = grouped_logs['number_of_proposals'].fillna(0).astype(int)
grouped_logs['num_users'] = grouped_logs['num_users'].fillna(1).astype(int)
grouped_logs['storeprop_times'] = grouped_logs['storeprop_times'].fillna(0)
grouped_logs['propose_times'] = grouped_logs['propose_times'].fillna(0)
grouped_logs['propose_sizes'] = grouped_logs['propose_sizes'].fillna(0)


# Calculate latency from timestamps
def calculate_latency(row):
    epoch_timestamp = row['epoch_generating_timestamp']
    if pd.isna(epoch_timestamp) or not isinstance(row['other_timestamps'], list):
        return []
    
    if isinstance(row['welcome_timestamps'], list):
        return [ts - epoch_timestamp for ts in (row['other_timestamps'] + row['welcome_timestamps']) if pd.notna(ts)]
    else:
        return [ts - epoch_timestamp for ts in row['other_timestamps'] if pd.notna(ts)]

grouped_logs['latency'] = grouped_logs.apply(calculate_latency, axis=1)

def remove_outliers(latencies):
    if len(latencies) == 0:
        return latencies
    Q1 = pd.Series(latencies).quantile(0.25)
    Q3 = pd.Series(latencies).quantile(0.75)
    IQR = Q3 - Q1
    lower_bound = Q1 - 1.5 * IQR
    upper_bound = Q3 + 1.5 * IQR
    return [latency for latency in latencies if lower_bound <= latency <= upper_bound]

if "outliers" in transforms:
    # Aplicar la función para eliminar outliers en las latencias
    grouped_logs['latency'] = grouped_logs['latency'].apply(remove_outliers)

def calculate_latency_statistics(latencies):
    if len(latencies) == 0:
        return pd.Series([None, None], index=['mean_latency', 'max_latency'])
    return pd.Series([pd.Series(latencies).mean(), pd.Series(latencies).max()],
                     index=['mean_latency', 'max_latency'])

# Add mean an max latency columns in seconds
stats = grouped_logs['latency'].apply(calculate_latency_statistics)
grouped_logs = pd.concat([grouped_logs, stats], axis=1)
grouped_logs['mean_latency'] = pd.to_numeric(grouped_logs['mean_latency'], errors='coerce') / 1e3
grouped_logs['max_latency'] = pd.to_numeric(grouped_logs['max_latency'], errors='coerce') / 1e3

# order dataframe
grouped_logs = grouped_logs.sort_values(by=['group', 'epoch']).reset_index(drop=True)

# add column with process times
grouped_logs['size'] = pd.to_numeric(grouped_logs['size'], errors='coerce')
grouped_logs['next_size'] = grouped_logs['size'].shift(-1)
grouped_logs['next_update_gen_time'] = grouped_logs['gen_time'].shift(-1)
grouped_logs['next_update_process_time'] = grouped_logs['process_times'].shift(-1)

#cost per update
def calculate_mean(row):
    if row['epoch'] == 0 or row['number_of_proposals'] == 0: return 0
    return (row['propose_sizes'] * row['number_of_proposals'] + row['next_size']) / (row['number_of_proposals'])

def calculate_processing_elapsed(row):
    if row['epoch'] == 0 or row['number_of_proposals'] == 0: return 0
    return (row['storeprop_times'] * row['number_of_proposals'] + row['next_update_process_time']) / (row['number_of_proposals'])

def calculate_gen_elapsed(row):
    if row['epoch'] == 0 or row['number_of_proposals'] == 0: return 0
    return (row['propose_times'] * row['number_of_proposals'] + row['next_update_gen_time']) / (row['number_of_proposals'])

grouped_logs['sizes_mean'] = grouped_logs.apply(calculate_mean, axis=1)
grouped_logs['processing_elapsed_mean'] = grouped_logs.apply(calculate_processing_elapsed, axis=1)
grouped_logs['gen_elapsed_mean'] = grouped_logs.apply(calculate_gen_elapsed, axis=1)

# Remove intermediate columns
grouped_logs = grouped_logs.drop(columns=['next_size'])
grouped_logs = grouped_logs.drop(columns=['next_update_gen_time'])
grouped_logs = grouped_logs.drop(columns=['next_update_process_time'])

if "remove_last" in transforms:
    idx_max_epoch = grouped_logs.groupby('group')['epoch'].idxmax()
    grouped_logs = grouped_logs.drop(idx_max_epoch)

# print and save`
print(grouped_logs)
grouped_logs.to_csv('grouped_logs.csv', index=False)