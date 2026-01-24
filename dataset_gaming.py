import pandas as pd
import numpy as np
import joblib

path_to_dataset = "C:/Users/nedob/Programming/Data Science/Datasets/CICIDS2017/res_1"
TRAIN_CSV_PATH = f"{path_to_dataset}/train.csv"
TEST_CSV_PATH  = f"{path_to_dataset}/test.csv"
CLASS_LIST = ['Normal Traffic', 'DoS', 'DDoS', 'Bots', 'Port Scanning', 'Brute Force', 'Web Attacks']
xgb_clf = joblib.load("xgb_model.joblib")
scaler = joblib.load("scaler.joblib")

df = pd.read_csv(TRAIN_CSV_PATH)
name_columns = list(df.columns.values)

probs_unchanged = []
probs_without_tcp = []

for mal_type in CLASS_LIST[1:]:
       malicious_traffic = df[df['Attack Type'] == mal_type].iloc[:20, :-1]
       x_scaled = scaler.transform(malicious_traffic)
       probs = xgb_clf.predict_proba(x_scaled)
       i_mal_type = CLASS_LIST.index(mal_type)
       print(probs[:, i_mal_type] * 100)
       probs_unchanged.append(probs[:, i_mal_type] * 100)

for mal_type in CLASS_LIST[1:]:
       malicious_traffic = df[df['Attack Type'] == mal_type].iloc[:20, :-1]
       malicious_traffic[['FIN Flag Count', 'PSH Flag Count', 'ACK Flag Count']] = 0
       x_scaled = scaler.transform(malicious_traffic)
       probs = xgb_clf.predict_proba(x_scaled)
       i_mal_type = CLASS_LIST.index(mal_type)
       print(probs[:, i_mal_type] * 100)
       probs_without_tcp.append(probs[:, i_mal_type] * 100)

probs_unchanged = np.array(probs_unchanged)
probs_without_tcp = np.array(probs_without_tcp)
difference = probs_without_tcp - probs_unchanged
average_deviation = np.mean(difference, axis=1)
print(average_deviation.shape)
for a, b in zip(CLASS_LIST[1:], average_deviation):
       print(a, b)


# l = ports_scanning.iloc[201].tolist()
# print([float(i) for i in l[:-1]])
# print(ports_scanning.iloc[201])

columns = ['Destination Port', 'Flow Duration', 'Total Fwd Packets',
       'Total Length of Fwd Packets', 'Fwd Packet Length Max',
       'Fwd Packet Length Min', 'Fwd Packet Length Mean',
       'Fwd Packet Length Std', 'Bwd Packet Length Max',
       'Bwd Packet Length Min', 'Bwd Packet Length Mean',
       'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
       'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
       'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
       'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
       'Bwd IAT Max', 'Bwd IAT Min', 'Fwd Header Length', 'Bwd Header Length',
       'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length',
       'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
       'Packet Length Variance', 'FIN Flag Count', 'PSH Flag Count',
       'ACK Flag Count', 'Average Packet Size', 'Subflow Fwd Bytes',
       'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
       'min_seg_size_forward', 'Active Mean', 'Active Max', 'Active Min',
       'Idle Mean', 'Idle Max', 'Idle Min']



# a = [80.0, 67593590.0, 6.0, 337.0, 319.0, 0.0, 56.16666667, 128.7950568, 8688.0, 0.0, 1932.5, 3506.021777, 176.5256143, 0.177531627, 6144871.818, 20300000.0, 67400000.0, 8.0, 67500000.0, 13500000.0, 30200000.0, 67400000.0, 85.0, 67600000.0, 13500000.0, 30100000.0, 67400000.0, 168.0, 164.0, 200.0, 0.088765813, 0.088765813, 0.0, 8688.0, 918.3076923, 2466.566925, 6083952.397, 1.0, 0.0, 0.0, 994.8333333, 337.0, 0.0, 235.0, 3.0, 20.0, 11028.0, 11028.0, 11028.0, 67400000.0, 67400000.0, 67400000.0]
# b = [80.0, 60133256.0, 10.0, 449.0, 316.0, 4.0, 44.900001525878906, 90.49690246582031, 0.0, 0.0, 0.0, 0.0, 7.466750144958496, 0.1662973314523697, 6681473.0, 5943591.0, 12013256.0, 0.95367431640625, 60133256.0, 6681473.0, 5943591.0, 12013256.0, 0.95367431640625, 0.0, 0.0, 0.0, 0.0, 0.0, 400.0, 0.0, 0.1662973314523697, 0.0, 4.0, 316.0, 44.900001525878906, 90.49690246582031, 8189.68994140625, 0.0, 0.0, 0.0, 44.900001525878906, 449.0, 0.0, 0.0, 1.0, 276.0, 0.07275152206420898, 0.09770607948303223, 0.04779696464538574, 11.997550010681152, 12.013256072998047, 11.958656311035156]

# for i, j, k in zip(columns, a, b):
#     print(i, round(j, 2), round(k, 2))
