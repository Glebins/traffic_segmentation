# train.py

from torch.utils.data import DataLoader, WeightedRandomSampler
import torch
import torch.nn as nn

from dataset import load_datasets, FlowDataset
from model import MLPNet


def train_model():
    # 1. Загружаем данные
    (X_train, y_train), (X_test, y_test), class_weights, scaler, class_list = load_datasets()
    input_dim = X_train.shape[1]
    num_classes = len(class_list)

    # 2. Создаём Dataset и рассчитываем веса для каждого сэмпла
    train_ds = FlowDataset(X_train, y_train)
    test_ds = FlowDataset(X_test, y_test)

    # Расчитываем частоту каждого класса в y_train
    counts = torch.bincount(torch.tensor(y_train, dtype=torch.long), minlength=num_classes).float()
    # пусть weight_per_class[i] = 1 / counts[i]
    weight_per_class = 1.0 / counts
    # формируем вес для каждого сэмпла
    sample_weights = weight_per_class[torch.tensor(y_train, dtype=torch.long)]
    sampler = WeightedRandomSampler(
        weights=sample_weights,
        num_samples=len(sample_weights),
        replacement=True
    )

    # 3. DataLoader: передаём sampler вместо shuffle
    train_loader = DataLoader(train_ds, batch_size=128, sampler=sampler)
    test_loader = DataLoader(test_ds, batch_size=128, shuffle=False)

    # 4. Инициализация модели, loss, optimizer
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = MLPNet(input_dim, num_classes).to(device)
    criterion = nn.CrossEntropyLoss(weight=class_weights.to(device))
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)

    # 5. Обучение
    for epoch in range(10):
        model.train()
        total_loss = 0.0
        for xb, yb in train_loader:
            xb, yb = xb.to(device), yb.to(device)
            logits = model(xb)
            loss = criterion(logits, yb)

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        print(f'Epoch {epoch + 1}: Loss = {total_loss:.4f}')

        # 6. Сохраняем checkpoint
        torch.save({
            'model_state_dict': model.state_dict(),
            'scaler': scaler,
            'class_list': class_list,
        }, f'mlp_model_{epoch}.pth')


if __name__ == '__main__':
    train_model()




# train.py

# import xgboost as xgb
# import joblib
# import numpy as np
# from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
#
# from dataset import load_datasets  # предполагается, что dataset.py уже включает отбор нужных признаков
#
# # ═════════════ Параметры ═══════════════════════════════════════════════════════
# # Путь для сохранения обученной модели
# MODEL_PATH = "xgb_model.joblib"
# SCALER_PATH = "scaler.joblib"
# # ═══════════════════════════════════════════════════════════════════════════════
#
# def train_model():
#     # 1. Загружаем данные (X_train, y_train), (X_test, y_test), class_weights, scaler, class_list
#     # (X_train, y_train), (X_test, y_test), class_weights, scaler, class_list = load_datasets()
#     (X_train, y_train), (X_test, y_test), scaler, class_list = load_datasets()
#
#     # 2. Инициализируем XGBoost-классификатор
#     # Используем параметры, подходящие для несбалансированных данных:
#     #   scale_pos_weight для каждого класса задаётся через class_weights,
#     #   но XGBClassifier поддерживает только один параметр scale_pos_weight (для двоичной).
#     # Для мультикласса балансировка через параметр 'weight' при обучении.
#
#     xgb_clf = xgb.XGBClassifier(
#         objective="multi:softprob",
#         num_class=len(class_list),
#         eval_metric="mlogloss",
#         use_label_encoder=False,
#         tree_method="hist",
#         # Можно задать другие гиперпараметры: max_depth, learning_rate и т.д.
#         max_depth=6,
#         learning_rate=0.2,
#         n_estimators=200,
#         subsample=0.8,
#         colsample_bytree=0.8,
#         reg_lambda=1.0,
#         random_state=42
#     )
#
#     # 3. Обучаем модель. Для передачи весов классов формируем словарь weight: пример вес =  инверсия частоты
#     #    Однако XGBClassifier принимает лишь единый параметр scale_pos_weight для двоичной классификации.
#     #    В мультиклассе можно передать 'weight' при обучении через DMatrix.
#     #    Проще: используем oversampling (WeightedRandomSampler) или манипуляции в load_datasets.
#     #    Но здесь для простоты оставим balanced классы через настройку параметра 'sample_weight'.
#     #    Можно подать sample_weight = class_weights[y_train].
#
#     # sample_weight = class_weights.numpy()[y_train]
#
#     xgb_clf.fit(
#         X_train,
#         y_train,
#         # sample_weight=sample_weight,
#         verbose=False
#     )
#
#     # 4. Сохраняем обученную модель
#     joblib.dump(xgb_clf, MODEL_PATH)
#     joblib.dump(scaler, SCALER_PATH)
#     print(f"Модель XGBoost сохранена в {MODEL_PATH}")
#
#     # 5. Оценим на тестовом наборе сразу же и выведем метрики
#     y_pred = xgb_clf.predict(X_test)
#     y_prob = xgb_clf.predict_proba(X_test)
#
#     acc = accuracy_score(y_test, y_pred)
#     print(f"\n=== Accuracy на тесте: {acc:.4f} ===\n")
#
#     print("=== Classification Report ===")
#     print(classification_report(y_test, y_pred, target_names=class_list, digits=4))
#
#     print("=== Confusion Matrix ===")
#     print(confusion_matrix(y_test, y_pred))
#
#
# if __name__ == "__main__":
#     train_model()

