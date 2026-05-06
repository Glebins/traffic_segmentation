import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

CSV_PATH = "balanced_only_quiet.csv"

def read_df(csv_path=CSV_PATH):
    df = pd.read_csv(csv_path).iloc[:, [10, 11, 12, 13, 16, 17, 20, 21, 22, 23, 24, 26, 40, 41, 50, 59, 60]]
    return df

# ==========================================
# 1. АРХИТЕКТУРА AUTOENCODER
# ==========================================
class NetworkAE(nn.Module):
    def __init__(self, input_dim):
        super(NetworkAE, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 8)
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Linear(32, input_dim)
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded
    

# ==========================================
# 2. КЛАСС ДЛЯ ПРИМЕНЕНИЯ ОБУЧЕННОЙ МОДЕЛИ
# ==========================================
class AnomalyDetector:
    def __init__(self, model_path="network_ae.pth", scaler_path="scaler_ae.pkl", threshold_path="threshold_ae.npy"):
        self.scaler = joblib.load(scaler_path)
        self.threshold = np.load(threshold_path)

        input_dim = 17
        self.model = NetworkAE(input_dim)
        self.model.load_state_dict(torch.load(model_path))
        self.model.eval()
        
    def _preprocess(self, flow_dict):
        data = np.array(flow_dict).reshape(1, -1)
        data_scaled = self.scaler.transform(data)

        return torch.FloatTensor(data_scaled)

    def check_anomaly(self, flow_dict):
        input_tensor = self._preprocess(flow_dict)
        
        with torch.no_grad():
            reconstructed = self.model(input_tensor)
            mse = torch.mean((input_tensor - reconstructed)**2).item()
            
        is_anomaly = mse > self.threshold
        return is_anomaly, mse

# ==========================================
# 3. ПОДГОТОВКА ДАННЫХ
# ==========================================
def preprocess_data(df):
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(df)
    
    return scaled_data, scaler

# ==========================================
# 4. ЦИКЛ ОБУЧЕНИЯ
# ==========================================
def train_model():
    df = read_df()
    X, scaler = preprocess_data(df)
    
    input_dim = X.shape[1]
    model = NetworkAE(input_dim)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=3e-4)
    
    X_tensor = torch.FloatTensor(X)
    loader = DataLoader(TensorDataset(X_tensor), batch_size=128, shuffle=True)
    
    print(f"Starting training on {X.shape[0]} flows with {input_dim} features...")
    
    for epoch in range(100):
        model.train()
        total_loss = 0
        for batch in loader:
            inputs = batch[0]
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, inputs)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        
        if epoch % 10 == 0:
            print(f"Epoch {epoch}, Loss: {total_loss/len(loader):.6f}")
    
    torch.save(model.state_dict(), "network_ae.pth")
    joblib.dump(scaler, "scaler_ae.pkl")
    print("Model and Scaler saved.")

    model.eval()
    with torch.no_grad():
        preds = model(X_tensor)
        errors = torch.mean((X_tensor - preds)**2, dim=1).numpy()
        threshold = np.percentile(errors, 99)
        print(f"Suggested Anomaly Threshold: {threshold:.6f}")
        np.save("threshold_ae.npy", threshold)

if __name__ == '__main__':
    train_model()

    detector = AnomalyDetector()
    
    # Пример данных нового потока - UDP flood
    # new_flow = [80, 850724.9355316162, 3000, 23547223, 7849.074333333333, 4064.4541207245206, 0.0, 0.0, 27679008.827083915, 3526.4042168051724, 283.6695350222128, 46014.07051086426, 3526.4042168051724, 0.0, 7849.074333333333, 0.0, 0.0]

    logs_malw = read_df('./flow_features_malw.csv').to_numpy().tolist()
    # print(logs_malw)

    print(f"Threshold: {detector.threshold:.2f}")

    for i, flow in enumerate(logs_malw):
        is_anomaly, score = detector.check_anomaly(flow)

        res_str = f"{i + 2} "

        res_str += f"Flow Score (MSE): {score:.2f}"
        
        if is_anomaly:
            res_str += " >>> ALERT: Anomaly Detected! <<< "
        else:
            res_str += " Flow is normal."

        print(res_str)
