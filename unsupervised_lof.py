import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import LocalOutlierFactor
import joblib

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

CSV_PATH = "balanced_only_quiet.csv"

def read_df(csv_path=CSV_PATH):
    df = pd.read_csv(csv_path).iloc[:, [10, 11, 12, 13, 16, 17, 20, 21, 22, 23, 24, 26, 40, 41, 50, 59, 60]]
    return df


# ==========================================
# 1. КЛАСС ДЛЯ ПРИМЕНЕНИЯ МОДЕЛИ
# ==========================================
class AnomalyDetectorLOF:
    def __init__(self, model_path="lof_model.pkl", 
                 scaler_path="scaler_lof.pkl", 
                 threshold_path="threshold_lof.npy"):
        
        self.scaler = joblib.load(scaler_path)
        self.threshold = np.load(threshold_path)
        self.model = joblib.load(model_path)
        
    def _preprocess(self, flow_dict):
        data = np.array(flow_dict).reshape(1, -1)
        return self.scaler.transform(data)
    
    def check_anomaly(self, flow_dict):
        data_scaled = self._preprocess(flow_dict)
        
        # score = self.model.negative_outlier_factor_[0] if hasattr(self.model, 'negative_outlier_factor_') else \
        #         self.model.score_samples(data_scaled)[0]

        score = self.model.score_samples(data_scaled)[0]
        
        is_anomaly = score < self.threshold
        return is_anomaly, score


# ==========================================
# 2. ПОДГОТОВКА ДАННЫХ
# ==========================================
def preprocess_data(df):
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(df)
    return scaled_data, scaler


# ==========================================
# 3. ОБУЧЕНИЕ LOF
# ==========================================
def train_lof():
    df = read_df()
    X, scaler = preprocess_data(df)
    
    print(f"Training Local Outlier Factor on {X.shape[0]} samples...")
    
    model = LocalOutlierFactor(
        n_neighbors=45,
        contamination=0.01,
        novelty=True,
        n_jobs=-1,
    )
    
    model.fit(X)
    
    joblib.dump(model, "lof_model.pkl")
    joblib.dump(scaler, "scaler_lof.pkl")
    print("LOF model and scaler saved.")
    
    # Порог
    scores = model.negative_outlier_factor_
    threshold = np.percentile(scores, 1)
    
    print(f"Suggested Anomaly Threshold: {threshold:.6f}")
    np.save("threshold_lof.npy", threshold)
    
    return model, scaler, threshold


if __name__ == '__main__':
    train_lof()
    
    detector = AnomalyDetectorLOF()
    
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
    