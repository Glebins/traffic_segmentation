import numpy as np
import pandas as pd

path_to_dataset = "C:/Users/nedob/Programming/Data Science/Datasets/CICIDS2017/res_1"
file = 'train'

ds = pd.read_csv(f"{path_to_dataset}/{file}.csv")

qw = ds[ds["Attack Type"] == "Port Scanning"].iloc[3, :-1]

# print(f"[{','.join(list(map(str, qw.values.tolist())))}]")
print(ds.columns)

exit()


import pandas as pd
from sklearn.model_selection import train_test_split

# ─────────── Параметры ─────────────────────────────────────────────────────────
path_to_dataset = "C:/Users/nedob/Programming/Data Science/Datasets/CICIDS2017"
TRAIN_CSV = f"{path_to_dataset}/res_1/train.csv"
TEST_CSV  = f"{path_to_dataset}/res_1/test.csv"
INPUT_CSV = f"{path_to_dataset}/cicids2017_cleaned.csv"    # <- Замените на путь к общему CSV
TEST_SIZE = 0.2                              # <- Доля тестовой выборки
# ───────────────────────────────────────────────────────────────────────────────

def main():
    # 1. Чтение общего очищенного CSV
    df = pd.read_csv(INPUT_CSV)
    if 'Attack Type' not in df.columns:
        raise ValueError("В таблице отсутствует колонка 'Label'.")

    # 2. Разбиение с сохранением распределения по классам (stratify по Label)
    train_df, test_df = train_test_split(
        df,
        test_size=TEST_SIZE,
        stratify=df['Attack Type'],
        random_state=42
    )

    # 3. Сохранение результатов
    train_df.to_csv(TRAIN_CSV, index=False)
    test_df.to_csv(TEST_CSV, index=False)
    print(f"Train ({len(train_df)} строк) сохранён в: {TRAIN_CSV}")
    print(f"Test  ({len(test_df)} строк) сохранён в: {TEST_CSV}")

if __name__ == "__main__":
    main()


# """
# prepare_dataset.py
#
# Скрипт для подготовки общего CSV внутри CICIDS-2017 и разбиения на train/test.
#
# Входные параметры задаются непосредственно в коде:
#     INPUT_DIR  – путь к папке с CSV-файлами CICIDS-2017 (разделёнными по дням).
#     OUTPUT_DIR – путь к папке, куда сохранить итоговый CSV и train/test.
#     TEST_SIZE  – доля тестовой выборки (float от 0 до 1).
#
# Результат:
#     OUTPUT_DIR/
#         ├── CICIDS2017_all.csv
#         ├── train.csv
#         └── test.csv
# """
#
# import os
# import glob
#
# import pandas as pd
# import numpy as np
# from sklearn.model_selection import train_test_split
#
# # ════════════════════════════════════════════════════════════════════════════
# # Параметры (задайте здесь нужные пути и долю тестовой выборки)
# INPUT_DIR = path_to_dataset     # <- Задайте путь к папке с CSV-файлами CICIDS-2017
# OUTPUT_DIR = path_to_dataset + "/res/"  # <- Задайте путь для сохранения итоговых файлов
# TEST_SIZE = 0.2                      # <- Доля тестовой выборки (например, 0.2 = 20%)
# # ════════════════════════════════════════════════════════════════════════════
#
# # Словарь преобразования оригинальных меток CICIDS-2017 в укрупнённые классы
# ATTACK_MAPPING = {
#     'BENIGN':                   'Normal',
#     'DoS Hulk':                 'DoS',
#     'DoS GoldenEye':            'DoS',
#     'DoS slowloris':            'DoS',
#     'DoS Slowhttptest':         'DoS',
#     'DDoS':                     'DDoS',
#     'PortScan':                 'PortScan',
#     'Infiltration':             'Infiltration',
#     'FTP-Patator':              'BruteForce',
#     'SSH-Patator':              'BruteForce',
#     'Web Attack � Brute Force': 'BruteForce',
#     'Web Attack � XSS':         'BruteForce',
#     'Web Attack � Sql Injection':'BruteForce',
#     'Bot':                      'Botnet',
#     # При необходимости можно добавить другие метки
# }
#
# # Список целевых укрупнённых классов
# TARGET_CLASSES = [
#     'Normal',
#     'DoS',
#     'DDoS',
#     'Botnet',
#     'PortScan',
#     'BruteForce',
#     'Infiltration',
# ]
#
# def load_and_merge_csvs(input_dir):
#     """
#     Считывает все CSV-файлы из input_dir и конкатенирует их в один DataFrame.
#     Возвращает объединённый DataFrame.
#     """
#     pattern = os.path.join(input_dir, '*.csv')
#     file_list = glob.glob(pattern)
#     if not file_list:
#         raise FileNotFoundError(f'В папке "{input_dir}" не найдено CSV-файлов.')
#
#     df_list = []
#     for fpath in file_list:
#         print(f'Читаем "{fpath}" ...')
#         df = pd.read_csv(fpath)
#         df_list.append(df)
#     merged_df = pd.concat(df_list, ignore_index=True)
#     print(f'Всего строк после объединения: {len(merged_df)}')
#     return merged_df
#
# def map_labels(df):
#     """
#     Преобразует колонку 'Label' в укрупнённые TARGET_CLASSES через ATTACK_MAPPING.
#     Строки, чьи метки не входят в ATTACK_MAPPING, отбрасываются.
#     """
#     df = df.copy()
#     df[' Label_orig'] = df[' Label']  # сохраняем оригинал, на случай отладки
#     df[' Label'] = df[' Label'].map(ATTACK_MAPPING)
#     # Оставляем только строки, где Label преобразовался в один из TARGET_CLASSES
#     df = df[df[' Label'].isin(TARGET_CLASSES)]
#     print('После фильтрации по целевым классам:')
#     print(df[' Label'].value_counts(dropna=False))
#     return df
#
# def stratified_split(df, test_size):
#     """
#     Делит DataFrame на train и test с указанным test_size,
#     сохраняя пропорции TARGET_CLASSES (stratify по 'Label').
#     """
#     X = df.drop(columns=[' Label'])
#     y = df[' Label']
#
#     X_train, X_test, y_train, y_test = train_test_split(
#         X, y,
#         test_size=test_size,
#         stratify=y,
#         random_state=42
#     )
#     print(f'Train: {len(X_train)} строк, Test: {len(X_test)} строк')
#     print('Распределение классов в train:')
#     print(y_train.value_counts())
#     print('Распределение классов в test:')
#     print(y_test.value_counts())
#
#     # Собираем обратно DataFrame с колонкой Label
#     train_df = X_train.copy()
#     train_df[' Label'] = y_train.values
#     test_df = X_test.copy()
#     test_df[' Label'] = y_test.values
#
#     return train_df, test_df
#
# def main():
#     # Проверяем директории
#     if not os.path.isdir(INPUT_DIR):
#         raise FileNotFoundError(f'Входная папка не найдена: {INPUT_DIR}')
#     os.makedirs(OUTPUT_DIR, exist_ok=True)
#
#     # 1) Объединяем CSV-файлы
#     merged_df = load_and_merge_csvs(INPUT_DIR)
#
#     # 2) Преобразуем метки в укрупнённые классы
#     processed_df = map_labels(merged_df)
#
#     # 3) Сохраняем объединённый CSV (с укрупнёнными метками)
#     all_csv_path = os.path.join(OUTPUT_DIR, 'CICIDS2017_all.csv')
#     processed_df.to_csv(all_csv_path, index=False)
#     print(f'Объединённый CSV сохранён в "{all_csv_path}"')
#
#     # 4) Разбиваем на train/test со stratify
#     train_df, test_df = stratified_split(processed_df, test_size=TEST_SIZE)
#
#     # 5) Сохраняем train.csv и test.csv
#     train_csv_path = os.path.join(OUTPUT_DIR, 'train.csv')
#     test_csv_path = os.path.join(OUTPUT_DIR, 'test.csv')
#     train_df.to_csv(train_csv_path, index=False)
#     test_df.to_csv(test_csv_path, index=False)
#     print(f'Train CSV сохранён в "{train_csv_path}"')
#     print(f'Test CSV сохранён в "{test_csv_path}"')
#
# if __name__ == '__main__':
#     main()

