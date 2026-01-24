# analyze_flow_log.py

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# Путь к файлу логов
LOG_PATH = "flow_log.csv"

def main():
    # 1) Считываем лог
    df = pd.read_csv(LOG_PATH, parse_dates=["timestamp"])
    df = df.dropna(subset=["score"])
    df["score"] = df["score"].astype(float)
    df["proc_name"] = df["proc_name"].fillna("Unknown").astype(str)

    # 2) Группируем по proc_name и считаем статистики + количество потоков
    stats = df.groupby("proc_name")["score"].agg(
        min_score="min",
        mean_score="mean",
        max_score="max",
        count_flows="count"
    ).reset_index()

    # 3) Сортируем процессы по убыванию среднего скора
    stats = stats.sort_values("mean_score", ascending=False).reset_index(drop=True)

    # 4) Подготавливаем таблицу для вывода в терминал (на русском)
    display_df = stats.copy()
    display_df["min_score"] = display_df["min_score"].map("{:.4f}".format)
    display_df["mean_score"] = display_df["mean_score"].map("{:.4f}".format)
    display_df["max_score"] = display_df["max_score"].map("{:.4f}".format)
    display_df["count_flows"] = display_df["count_flows"].astype(int)
    display_df = display_df.rename(columns={
        "proc_name": "Процесс",
        "min_score": "Мин. скор",
        "mean_score": "Сред. скор",
        "max_score": "Макс. скор",
        "count_flows": "Число потоков"
    })
    print("\n=== Статистика по процессам ===")
    print(display_df.to_string(index=False))

    # 5) Строим график
    norm_counts = (stats["count_flows"] - stats["count_flows"].min()) / (
            stats["count_flows"].max() - stats["count_flows"].min()
    )
    cmap = plt.get_cmap("viridis")
    bar_colors = cmap(norm_counts)

    sns.set_style("whitegrid")
    fig, ax = plt.subplots(figsize=(10, max(2, len(stats) * 0.3)))

    err_left = stats["mean_score"] - stats["min_score"]
    err_right = stats["max_score"] - stats["mean_score"]
    xerr = [err_left.values, err_right.values]

    ax.barh(
        y=np.arange(len(stats)),
        width=stats["mean_score"],
        xerr=xerr,
        color=bar_colors,
        ecolor="gray",
        capsize=3
    )

    ax.set_yticks(np.arange(len(stats)))
    ax.set_yticklabels(stats["proc_name"], fontfamily="sans-serif")
    ax.set_xlabel("Скор", fontfamily="sans-serif")
    ax.set_title("Средний скор для каждого процесса (усы = мин/макс)\n(цвет ~ число потоков)", fontfamily="sans-serif")

    sm = plt.cm.ScalarMappable(cmap=cmap, norm=plt.Normalize(
        vmin=stats["count_flows"].min(), vmax=stats["count_flows"].max()
    ))
    sm.set_array([])
    cbar = fig.colorbar(sm, ax=ax, pad=0.02)
    cbar.set_label("Число потоков", fontfamily="sans-serif")

    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()
