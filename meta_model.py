import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import joblib
from sklearn.linear_model import LogisticRegression

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

# ==========================================
# 1. АРХИТЕКТУРА AUTOENCODER
# ==========================================
class NetworkAE(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32), nn.BatchNorm1d(32), nn.ReLU(),
            nn.Linear(32, 16), nn.ReLU(), nn.Linear(16, 8)
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16), nn.ReLU(), nn.Linear(16, 32),
            nn.BatchNorm1d(32), nn.ReLU(), nn.Linear(32, input_dim)
        )
    def forward(self, x):
        return self.decoder(self.encoder(x))


# ==========================================
# 2. КАЛИБРОВКА
# ==========================================
class ScoreCalibrator:
    def __init__(self, threshold):
        self.threshold = threshold

    def scale(self, raw_value, is_inverse=False):
        val = -raw_value if is_inverse else raw_value
        thr = -self.threshold if is_inverse else self.threshold
        # Более стабильная сигмоида
        return 1 / (1 + np.exp(-(val - thr) / (abs(thr) + 1e-8) * 6))


def train_meta_model(benign_csv_path, models_dir="./"):
    """
    Обучает мета-модель (Logistic Regression) поверх базовых моделей.
    """
    # ====================== ЗАГРУЗКА МОДЕЛЕЙ ======================
    xgb_clf = joblib.load(f"{models_dir}xgb_model.joblib")
    xgb_scaler = joblib.load(f"{models_dir}scaler.joblib")
    
    ae_model = NetworkAE(input_dim=17)
    ae_model.load_state_dict(torch.load(f"{models_dir}network_ae.pth", map_location='cpu'))
    ae_model.eval()
    
    ae_scaler = joblib.load(f"{models_dir}scaler_ae.pkl")
    ae_thr = np.load(f"{models_dir}threshold_ae.npy").item()   # .item() на всякий случай
    
    if_model = joblib.load(f"{models_dir}isolation_forest.pkl")
    if_scaler = joblib.load(f"{models_dir}scaler_if.pkl")
    if_thr = np.load(f"{models_dir}threshold_if.npy").item()
    
    lof_model = joblib.load(f"{models_dir}lof_model.pkl")
    lof_scaler = joblib.load(f"{models_dir}scaler_lof.pkl")
    lof_thr = np.load(f"{models_dir}threshold_lof.npy").item()

    cal_ae = ScoreCalibrator(ae_thr)
    cal_if = ScoreCalibrator(if_thr)
    cal_lof = ScoreCalibrator(lof_thr)

    # ====================== ПОДГОТОВКА ДАННЫХ ======================
    # Используем только нужные колонки
    df = read_df(benign_csv_path)          # уже отбирает 17 числовых фичей для AE/IF/LOF
    df.fillna(0, inplace=True)

    # Для XGBoost нужны 52 фичи → загружаем полный df и отбираем их
    df_full = pd.read_csv(benign_csv_path)
    
    # Предполагаем, что FEATURES — список названий или индексов 52 фичей для XGB
    # Если у тебя есть список FEATURES, лучше использовать его:
    # X_xgb = df_full[FEATURES].values
    
    # Если FEATURES нет — оставляем как было (все числовые колонки после label/score и т.д.)
    numeric_cols = df_full.select_dtypes(include=[np.number]).columns.tolist()
    # Убираем служебные колонки, если они попали
    numeric_cols = [c for c in numeric_cols if c not in ['label', 'score', 'ts_utc', 'flow_key_pid', 'flow_proto', 'pid', 'total_pkts']]

    print(f"Используем {len(numeric_cols)} числовых фичей для XGBoost")

    X = df.values.astype(np.float32)                    # 17 фичей (AE/IF/LOF)
    X_xgb = df_full[numeric_cols].values.astype(np.float32)  # для XGBoost

    meta_features = []
    labels = []

    norm_results = []
    mal_results = []

    n_samples = min(3000, len(X))

    print("Generating meta-features for Normal traffic...")
    for i in range(n_samples):
        row = X[i:i+1]
        row_xgb = X_xgb[i:i+1]

        # XGBoost probability of malicious
        p_mal = 1 - xgb_clf.predict_proba(xgb_scaler.transform(row_xgb))[:, 0][0]

        # AE reconstruction error
        ae_in = torch.from_numpy(ae_scaler.transform(row))
        with torch.no_grad():
            recon = ae_model(ae_in)
        mse = torch.mean((ae_in - recon)**2, dim=1).item()
        s_ae = cal_ae.scale(mse)

        # Isolation Forest
        s_if = cal_if.scale(if_model.score_samples(if_scaler.transform(row)), is_inverse=True)

        # LOF
        s_lof = cal_lof.scale(lof_model.score_samples(lof_scaler.transform(row)), is_inverse=True)

        meta_features.append([p_mal, s_ae, s_if[0], s_lof[0]])
        norm_results.append([p_mal, s_ae, s_if[0], s_lof[0]])
        labels.append(0)

    print("Generating meta-features for Synthetic Anomalies...")
    for i in range(n_samples):
        row_orig = X[i].copy()
        row_xgb_orig = X_xgb[i].copy()
        
        # Портим ~35% признаков (6 из 17)
        idx_to_corrupt = np.random.choice(17, 6, replace=False)
        for idx in idx_to_corrupt:
            row_orig[idx] = row_orig[idx] * np.random.uniform(2.0, 5.0)

        idx_xgb_to_corrupt = np.random.choice(52, 15, replace=False)
        for idx in idx_xgb_to_corrupt:
            row_xgb_orig[idx] = row_xgb_orig[idx] * np.random.uniform(2.0, 5.0)

        row = row_orig.reshape(1, -1)
        row_xgb = row_xgb_orig.reshape(1, -1)

        p_mal = 1 - xgb_clf.predict_proba(xgb_scaler.transform(row_xgb))[:, 0][0]

        ae_in = torch.from_numpy(ae_scaler.transform(row))
        with torch.no_grad():
            recon = ae_model(ae_in)
        mse = torch.mean((ae_in - recon)**2, dim=1).item()

        s_ae = cal_ae.scale(mse)
        s_if = cal_if.scale(if_model.score_samples(if_scaler.transform(row)), is_inverse=True)
        s_lof = cal_lof.scale(lof_model.score_samples(lof_scaler.transform(row)), is_inverse=True)

        meta_features.append([p_mal, s_ae, s_if[0], s_lof[0]])
        mal_results.append([p_mal, s_ae, s_if[0], s_lof[0]])
        labels.append(1)

    # ====================== ОБУЧЕНИЕ МЕТА-МОДЕЛИ ======================
    print("Meta model learning has started")
    X_meta = np.array(meta_features, dtype=np.float32)
    y_meta = np.array(labels)

    meta_clf = LogisticRegression(
        class_weight='balanced',
        penalty='l2',
        C=0.1,
        solver='liblinear',
        max_iter=1000,
        random_state=42
    )
    meta_clf.fit(X_meta, y_meta)

    joblib.dump(meta_clf, f"{models_dir}meta_model.joblib")
    
    print("Meta-model trained successfully!")
    print(f"Coefficients (XGB_prob, AE, IF, LOF): {meta_clf.coef_[0]}")
    print(f"Intercept: {meta_clf.intercept_[0]:.4f}")

    print(f"Norm values: {np.array(norm_results).mean(0)}\nMal values: {np.array(mal_results).mean(0)}")

    # for ind, (i, j) in enumerate(zip(norm_results, mal_results)):
    #     diff = j[2] - i[2]
    #     if diff < 0:
    #         s = f"{ind}, {diff}, {i}, {j} <<<<<<<<<<<<<<<<<<<<<<<<<<"
    #         print(s)

    meta_df = pd.DataFrame(X_meta, columns=['xgb_prob', 'ae', 'if', 'lof'])
    meta_df['label'] = y_meta
    print(meta_df.corr())
    print("\nMean by label:\n", meta_df.groupby('label').mean())

    return meta_clf


def read_df(csv_path):
    cols = [10, 11, 12, 13, 16, 17, 20, 21, 22, 23, 24, 26, 40, 41, 50, 59, 60]
    df = pd.read_csv(csv_path, usecols=cols, dtype=np.float32)
    return df

train_meta_model('balanced_only_quiet.csv')
