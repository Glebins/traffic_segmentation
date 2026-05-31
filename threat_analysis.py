import torch
import torch.nn as nn
import numpy as np
import pandas as pd
import joblib
import os

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

# ==========================================
# 1. АРХИТЕКТУРА AUTOENCODER
# ==========================================
class NetworkAE(nn.Module):
    def __init__(self, input_dim):
        super(NetworkAE, self).__init__()
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
# 2. КАЛИБРОВКА (Confidence Scorer)
# ==========================================
class ScoreCalibrator:
    """Нормализует сырые выходы моделей в диапазон  относительно порога"""
    def __init__(self, threshold):
        self.threshold = threshold

    def scale(self, raw_value, is_inverse=False):
        # Для IF/LOF: меньше = аномальнее. Для AE/XGB: больше = аномальнее.
        val = -raw_value if is_inverse else raw_value
        thr = -self.threshold if is_inverse else self.threshold
        # Сигмоида: 0.5 на пороге, растет к 1 при усилении аномальности
        return 1 / (1 + np.exp(-(val - thr) / (abs(thr) + 1e-9) * 6))

# ==========================================
# 3. ИНТЕГРИРОВАННАЯ ГИБРИДНАЯ СИСТЕМА
# ==========================================
class HybridSecuritySystem:
    def __init__(self, models_dir="./"):
        self.models_dir = models_dir
        
        # 1. Загрузка Supervised (XGBoost)
        self.xgb_clf = self._safe_joblib_load(os.path.join(models_dir, "xgb_model.joblib"))
        self.xgb_scaler = self._safe_joblib_load(os.path.join(models_dir, "scaler.joblib"))
        self.has_xgb = self.xgb_clf is not None and self.xgb_scaler is not None
        
        # 2. Загрузка Autoencoder (AE)
        self.ae_scaler = self._safe_joblib_load(os.path.join(models_dir, "scaler_ae.pkl"))
        self.ae_threshold = self._safe_npy_load(os.path.join(models_dir, "threshold_ae.npy"))
        self.ae_model = None
        self.has_ae = False
        if self.ae_scaler is not None and self.ae_threshold is not None:
            try:
                self.ae_model = NetworkAE(input_dim=17)
                self.ae_model.load_state_dict(torch.load(os.path.join(models_dir, "network_ae.pth")))
                self.ae_model.eval()
                self.has_ae = True
            except Exception:
                self.ae_model = None
                self.has_ae = False

        # 3. Загрузка Isolation Forest (IF)
        self.if_model = self._safe_joblib_load(os.path.join(models_dir, "isolation_forest.pkl"))
        self.if_scaler = self._safe_joblib_load(os.path.join(models_dir, "scaler_if.pkl"))
        self.if_threshold = self._safe_npy_load(os.path.join(models_dir, "threshold_if.npy"))
        self.has_if = self.if_model is not None and self.if_scaler is not None and self.if_threshold is not None

        # 4. Загрузка Local Outlier Factor (LOF)
        self.lof_model = self._safe_joblib_load(os.path.join(models_dir, "lof_model.pkl"))
        self.lof_scaler = self._safe_joblib_load(os.path.join(models_dir, "scaler_lof.pkl"))
        self.lof_threshold = self._safe_npy_load(os.path.join(models_dir, "threshold_lof.npy"))
        self.has_lof = self.lof_model is not None and self.lof_scaler is not None and self.lof_threshold is not None

        # 5. Meta-model
        self.meta_model = self._safe_joblib_load(os.path.join(models_dir, "meta_model.joblib"))
        self.has_meta = self.meta_model is not None
        
        # Initialize calibrators only for available thresholds
        self.cal_ae = ScoreCalibrator(self.ae_threshold) if self.has_ae else None
        self.cal_if = ScoreCalibrator(self.if_threshold) if self.has_if else None
        self.cal_lof = ScoreCalibrator(self.lof_threshold) if self.has_lof else None

    def _safe_joblib_load(self, path):
        try:
            return joblib.load(path)
        except Exception:
            return None

    def _safe_npy_load(self, path):
        try:
            return np.load(path)
        except Exception:
            return None

    def instance_analyze_flow(self, flow_features):
        """Прогон потока через все модели и назначение статуса"""
        x_raw = np.array(flow_features).reshape(1, -1)
        
        prob_malicious = 0.0
        if self.has_xgb:
            try:
                x_xgb = self.xgb_scaler.transform(x_raw)
                xgb_probs = self.xgb_clf.predict_proba(x_xgb)
                prob_malicious = float(1.0 - xgb_probs[0][0])
            except Exception:
                prob_malicious = 0.0
        
        inds = np.array([10, 11, 12, 13, 16, 17, 20, 21, 22, 23, 24, 26, 40, 41, 50, 59, 60]) - 10
        x_raw = x_raw[:, inds]

        score_ae = 0.0
        if self.has_ae:
            try:
                x_ae = torch.FloatTensor(self.ae_scaler.transform(x_raw))
                with torch.no_grad():
                    reconstructed = self.ae_model(x_ae)
                    mse = torch.mean((x_ae - reconstructed)**2).item()
                score_ae = self.cal_ae.scale(mse)
            except Exception:
                score_ae = 0.0

        score_if = 0.0
        if self.has_if:
            try:
                x_if = self.if_scaler.transform(x_raw)
                if_raw = self.if_model.score_samples(x_if)
                score_if = self.cal_if.scale(if_raw, is_inverse=True)[0]
            except Exception:
                score_if = 0.0

        score_lof = 0.0
        if self.has_lof:
            try:
                x_lof = self.lof_scaler.transform(x_raw)
                lof_raw = self.lof_model.score_samples(x_lof)
                score_lof = self.cal_lof.scale(lof_raw, is_inverse=True)[0]
            except Exception:
                score_lof = 0.0

        available_scores = [s for s in (score_ae, score_if, score_lof) if s is not None]
        anomaly_consensus = sum(available_scores) / len(available_scores) if available_scores else 0.0

        meta_in = np.array([[prob_malicious, score_ae, score_if, score_lof]])
        if self.has_meta:
            try:
                final_threat_prob = self.meta_model.predict_proba(meta_in)[0][1]
            except Exception:
                final_threat_prob = prob_malicious if self.has_xgb else anomaly_consensus
        else:
            final_threat_prob = prob_malicious if self.has_xgb else anomaly_consensus
        
        # Финальный статус
        status = self.assign_final_threat_status(prob_malicious, final_threat_prob, anomaly_consensus)
        
        return {
            "status": status,
            "threat_prob": final_threat_prob,
            "anomaly_consensus": anomaly_consensus,
            "details": {
                "XGB_Malice": prob_malicious,
                "AE_Score": score_ae,
                "IF_Score": score_if,
                "LOF_Score": score_lof
            }
        }

    def assign_final_threat_status(self, xgb_prob, meta_prob, anomaly_consensus):
        """
        Анализ итогового значения и назначение категории опасности.
        Позволяет выявлять атаки Zero-Day при низком threat_prob, но высоком consensus.
        """
        strong_xgb = xgb_prob > 0.85
        good_xgb = xgb_prob > 0.65
        weak_xgb = xgb_prob < 0.35
        
        strong_meta = meta_prob > 0.85
        good_meta = meta_prob > 0.70
        moderate_meta = meta_prob > 0.50
        
        strong_anomaly = anomaly_consensus > 0.82
        good_anomaly = anomaly_consensus > 0.65
        moderate_anomaly = anomaly_consensus > 0.45

        # =============================================
        # 1. Критические случаи
        # =============================================
        if strong_meta and strong_xgb and strong_anomaly:
            return "CRITICAL: Confirmed Known Attack"
        
        if strong_meta and strong_xgb:
            return "CRITICAL: High-Confidence Known Attack"

        # =============================================
        # 2. Высокий уровень угрозы
        # =============================================
        if (strong_meta or (good_meta and strong_anomaly)) and good_xgb:
            return "HIGH: Known Attack with Strong Anomaly Confirmation"
        
        if strong_anomaly and weak_xgb and meta_prob > 0.65:
            return "HIGH: Likely Zero-Day / Unknown Anomaly"
        
        if strong_meta and weak_xgb:
            return "HIGH: Meta-Model Alert"

        # =============================================
        # 3. Средний уровень
        # =============================================
        if good_meta and good_anomaly:
            return "WARNING: Suspicious Activity (Meta + Anomaly)"
        
        if good_xgb and (good_anomaly or moderate_meta):
            return "WARNING: Potential Known Threat"
        
        if moderate_meta and moderate_anomaly and xgb_prob > 0.4:
            return "WARNING: Moderate Suspicion"

        # =============================================
        # 4. Низкий уровень
        # =============================================
        if meta_prob < 0.35 and anomaly_consensus < 0.40 and xgb_prob < 0.35:
            return "NORMAL: Legitimate Traffic"
        
        if meta_prob < 0.45 and anomaly_consensus < 0.50:
            return "NORMAL: Mostly Legitimate"

        # =============================================
        # 5. Остальные пограничные случаи
        # =============================================
        if meta_prob > 0.55 or anomaly_consensus > 0.55 or xgb_prob > 0.55:
            return "WARNING: Suspicious Activity"
        
        return "NORMAL: Likely Legitimate"

# Пример использования на "железе"
if __name__ == "__main__":
    detector = HybridSecuritySystem()
    # Загрузка тестового потока (17 признаков)
    # test_flow = [443,2232613.0867004395,9,7576,2367.0,24.0,841.7777777777778,936.994103832721,0.0,0.0,0.0,0.0,3393.33315079529,4.0311507863196425,279076.63583755493,652534.1850811996,2004147.0527648926,485.1818084716797,2232613.0867004395,279076.63583755493,652534.1850811996,2004147.0527648926,485.1818084716797,0.0,0.0,0.0,0.0,0.0,360,0,4.0311507863196425,0.0,24.0,2367.0,841.7777777777778,936.994103832721,877957.9506172838,0,0,0,841.7777777777778,7576,0,0,7,59,228466.03393554688,228466.03393554688,228466.03393554688,2004147.0527648926,2004147.0527648926,2004147.0527648926]
    
    # csv_to_import = './balanced_only_quiet.csv'
    csv_to_import = 'flow_features_malw_1.csv'
    logs_malw = pd.read_csv(csv_to_import).iloc[:, 10:].to_numpy().tolist()
    proc_names = pd.read_csv(csv_to_import).iloc[:, 6].tolist()

    # proc_names1 = pd.read_csv(csv_to_import).iloc[:, 6]
    # print(proc_names1.value_counts())
    # exit(0)

    for i, (flow, proc) in enumerate(zip(logs_malw, proc_names)):
        if proc != 'python':
            continue
        
        result = detector.instance_analyze_flow(flow)

        res_str = f"{i + 2} "
        res_str += f"{result}\n\n"

        # res_str += f"Verdict: {result['status']} (Prob: {result['threat_prob']:.2f})"

        print(res_str)
    
    # result = detector.instance_analyze_flow(test_flow)
    # print(f"Verdict: {result['status']} (Prob: {result['threat_prob']:.2f})")