import pandas as pd
from sklearn.neighbors import LocalOutlierFactor
import matplotlib
# 设置为非交互式后端，防止 WSL2 报错
matplotlib.use('Agg') 
import matplotlib.pyplot as plt

# 1. 加载 eBPF 采集到的数据
try:
    df = pd.read_csv("latency_data.csv")
    df['latency_ms'] = df['latency_ns'] / 1e6
except FileNotFoundError:
    print("错误：未找到 latency_data.csv，请先运行采集器。")
    exit()

# 2. 异常识别：使用 LOF 算法 (参考 2025 年最新异常检测研究 [1])
lof = LocalOutlierFactor(n_neighbors=20, contamination=0.05)
df['anomaly_score'] = lof.fit_predict(df[['latency_ms']])

# -1 代表异常，标记出来
anomalies = df[df['anomaly_score'] == -1]

# 3. 可视化并保存
plt.figure(figsize=(12, 6))
plt.plot(df.index, df['latency_ms'], label='Scheduling Latency (ms)', color='blue', alpha=0.5)
plt.scatter(anomalies.index, anomalies['latency_ms'], color='red', label='Detected Anomaly', marker='x')

plt.title("Cloud-Native Container Anomaly Detection (eBPF + LOF)")
plt.xlabel("Sample Sequence")
plt.ylabel("Latency (ms)")
plt.legend()
plt.grid(True)

# 保存到当前目录
output_file = "anomaly_report.png"
plt.savefig(output_file)
print(f"分析完成！图表已保存至当前目录：{output_file}")