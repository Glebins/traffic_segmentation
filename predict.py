# """
# predict.py
#
# Скрипт для загрузки обученной модели и оценки её качества на отложенной тестовой выборке.
#
# Использует готовый загрузчик из dataset.py: load_datasets().
# Предполагается, что train/test ранее были разбиты и нормализованы в load_datasets(),
# поэтому здесь просто извлекаем (X_test, y_test).
# """

import torch
import torch.nn.functional as F
import numpy as np
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from dataset import load_datasets       # Ваш модуль загрузки данных
from model import MLPNet                 # Класс модели из model.py

# ─────────── Параметры ─────────────────────────────────────────────────────────
MODEL_PATH = "mlp_model_7.pth"   # <- Путь к сохранённому чекпоинту из train.py
# ───────────────────────────────────────────────────────────────────────────────

def load_model_and_scaler(path, device):
    """
    Загружает checkpoint, возвращает:
     - экземпляр модели с загруженными весами (на device)
     - scaler (MinMaxScaler), сохранённый в чекпоинте
     - список имён классов (class_list)
    """
    checkpoint = torch.load(path, map_location=device, weights_only=False)
    class_list = checkpoint['class_list']
    scaler = checkpoint['scaler']
    # для определения input_dim:
    input_dim = scaler.n_features_in_
    num_classes = len(class_list)

    model = MLPNet(input_dim, num_classes).to(device)
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    return model, scaler, class_list

def main():
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    # 1. Загружаем модель и scaler
    model, scaler, class_list = load_model_and_scaler(MODEL_PATH, device)

    # 2. Получаем данные через ваш загрузчик: он уже отдаёт (X_train, y_train), (X_test, y_test)
    (_, _), (X_test, y_test), _, _, _ = load_datasets()

    # Преобразуем X_test в torch.Tensor и вычислим предсказания
    # (load_datasets уже вернул массивы float32, нормализованные)
    X_test_tensor = torch.from_numpy(X_test).to(device)  # shape (N, num_features)
    y_true = y_test                                   # numpy array, shape (N,)

    # 3. Инференс
    with torch.no_grad():
        logits = model(X_test_tensor)                          # shape (N, num_classes)
        probs = F.softmax(logits, dim=1).cpu().numpy()         # numpy array (N, num_classes)
        y_pred = np.argmax(probs, axis=1)                       # numpy array (N,)

    # 4. Считаем и выводим метрики
    acc = accuracy_score(y_true, y_pred)
    print(f"\n=== Accuracy на тесте: {acc:.4f} ===\n")

    print("=== Classification Report ===")
    print(classification_report(
        y_true,
        y_pred,
        target_names=class_list,
        digits=4
    ))

    print("=== Confusion Matrix ===")
    cm = confusion_matrix(y_true, y_pred)
    print(cm)

if __name__ == "__main__":
    main()

# predict.py

# import joblib
# import numpy as np
# import pandas as pd
# from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# from dataset import load_datasets

# # ═════════════ Параметры ═══════════════════════════════════════════════════════
# # Путь к сохранённой модели XGBoost
# MODEL_PATH = "xgb_model.joblib"
# SCALER_PATH = "scaler.joblib"
# # ═══════════════════════════════════════════════════════════════════════════════

# def main():
#     # 1. Загружаем модель
#     xgb_clf = joblib.load(MODEL_PATH)

#     # 2. Загружаем данные (игнорируем обучающую часть)
#     (X_train, y_train), (X_test, y_test), _, class_list = load_datasets()

#     # 3. Предсказание
#     y_pred = xgb_clf.predict(X_test)
#     y_prob = xgb_clf.predict_proba(X_test)

#     # 4. Вычисляем метрики
#     acc = accuracy_score(y_test, y_pred)
#     print(f"\n=== Accuracy на тесте: {acc:.4f} ===\n")

#     print("=== Classification Report ===")
#     print(classification_report(y_test, y_pred, target_names=class_list, digits=4))

#     print("=== Confusion Matrix ===")
#     print(confusion_matrix(y_test, y_pred))


# def check_instance():
#     X = np.array([80,35205792,203,43906,602,0,216.2857143,228.4931854,1068,0,694.0673077,362.5692639,3297.440376,8.720156047,115051.6078,328506.7186,3552634,4,35200000,174270.4851,391709.2126,3552634,692,35200000,341802.6117,517279.2935,3553279,4,6504,3336,5.76609667,2.954059378,0,1068,376.9123377,360.6318497,130055.3311,0,1,0,378.1400651,43906,29200,1176,101,32,0.0,0,0,0.0,0,0
#                   ]).reshape(1, -1)

#     xgb_clf = joblib.load(MODEL_PATH)
#     scaler = joblib.load(SCALER_PATH)

#     X_scaled = scaler.transform(X)

#     print(xgb_clf.predict_proba(X_scaled))


# if __name__ == "__main__":
#     check_instance()

