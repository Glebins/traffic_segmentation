"""
dataset.py

Модуль для загрузки и подготовки данных из уже объединённых и размеченных CSV-файлов:
- train.csv
- test.csv

Ожидается, что эти файлы уже содержат укрупнённые метки в колонке 'Label' (Normal, DoS, DDoS и т.д.).
Этот скрипт:
1. Считывает train.csv и test.csv.
2. Выделяет признаки (X) и метки (y).
3. Применяет Min-Max нормализацию к признакам на основе train.csv.
4. Вычисляет веса классов на train.csv для балансировки.
5. Возвращает подготовленные DataLoader’ы или массивы numpy/torch tensor.

Параметры (измените при необходимости):
    TRAIN_CSV_PATH – путь к train.csv
    TEST_CSV_PATH  – путь к test.csv
"""

import pandas as pd
import numpy as np

from sklearn.preprocessing import MinMaxScaler, RobustScaler, StandardScaler
from sklearn.utils.class_weight import compute_class_weight

import torch
from torch.utils.data import Dataset

# ════════════════════════════════════════════════════════════════════════════
# Параметры (укажите здесь пути к своим файлам)
path_to_dataset = "C:/Users/nedob/Programming/Data Science/Datasets/CICIDS2017/res_1"
TRAIN_CSV_PATH = f"{path_to_dataset}/train.csv"
TEST_CSV_PATH  = f"{path_to_dataset}/test.csv"
# ════════════════════════════════════════════════════════════════════════════

# Список укрупнённых классов (должен совпадать с тем, что использовался при подготовке)
CLASS_LIST = ['Normal Traffic', 'DoS', 'DDoS', 'Bots', 'Port Scanning', 'Brute Force', 'Web Attacks']

class FlowDataset(Dataset):
    """
    Простой Dataset для векторных признаков течений (flows).
    """
    def __init__(self, X: np.ndarray, y: np.ndarray):
        # X: numpy array размерности (n_samples, n_features)
        # y: numpy array размерности (n_samples,), целочисленные метки 0..len(CLASS_LIST)-1
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.long)

    def __len__(self):
        return len(self.y)

    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]

def load_datasets():
    """
    1. Считывает train.csv и test.csv.
    2. Применяет MinMaxScaler к признакам.
    3. Кодирует метки в целые числа (0..6) согласно CLASS_LIST.
    4. Вычисляет веса классов по train.csv.
    Возвращает:
        - (X_train, y_train): numpy arrays
        - (X_test, y_test): numpy arrays
        - class_weights: torch.Tensor размерности (num_classes,)
        - scaler: обученный MinMaxScaler (нужен при inference)
        - class_list: список имён классов
    """
    # 1. Читаем CSV
    df_train = pd.read_csv(TRAIN_CSV_PATH)
    df_test  = pd.read_csv(TEST_CSV_PATH)

    # df_train = df_train[FEATURE_LIST + ['Attack Type']]
    # df_test  = df_test[FEATURE_LIST + ['Attack Type']]
    # print(df_train.columns)

    # 2. Отделяем X и y
    #    Предполагаем, что 'Label' — последняя колонка, все остальные — признаки
    X_train = df_train.drop(columns=['Attack Type']).values.astype(np.float32)
    y_train = df_train['Attack Type'].map({name: idx for idx, name in enumerate(CLASS_LIST)}).values.astype(np.int64)

    X_test = df_test.drop(columns=['Attack Type']).values.astype(np.float32)
    y_test = df_test['Attack Type'].map({name: idx for idx, name in enumerate(CLASS_LIST)}).values.astype(np.int64)

    # 3. Нормализация Min-Max (обучаем scaler на train, применяем к обеим выборкам)
    scaler = RobustScaler()
    # scaler = MinMaxScaler()
    # scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    # 4. Вычисляем веса классов (по train)
    class_weights = compute_class_weight(
        class_weight='balanced',
        classes=np.arange(len(CLASS_LIST)),
        y=y_train
    )
    class_weights = torch.tensor(class_weights, dtype=torch.float32)

    # return (X_train_scaled, y_train), (X_test_scaled, y_test), class_weights, scaler, CLASS_LIST
    return (X_train_scaled, y_train), (X_test_scaled, y_test), scaler, CLASS_LIST
