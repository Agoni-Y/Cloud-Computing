from bcc import BPF
import time
import pandas as pd

# 1. 定义内核态 eBPF C 代码
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 定义哈希表存储进程进入就绪队列的时间戳
BPF_HASH(start, u32, u64);

// 钩子：当进程进入就绪状态时触发
// 修改后的 trace_enqueue，适配 tracepoint 的参数格式
int trace_enqueue(struct reserved_args *args) {
    // 在 tracepoint 中，我们可以直接通过 args 获取 PID（具体字段取决于内核定义）
    // 或者使用 bpf_get_current_pid_tgid() 获取当前触发唤醒的任务 PID
    u32 pid = bpf_get_current_pid_tgid(); 
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

// 钩子：当进程获得 CPU 开始执行时触发
int trace_run(struct pt_regs *ctx, struct task_struct *prev) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 *tsp, delta;

    tsp = start.lookup(&pid);
    if (tsp == 0) return 0; // 如果没记录开始时间，忽略

    delta = bpf_ktime_get_ns() - *tsp;
    // 此处可以将 delta (ns) 输出或存入 BPF 表中
    // 为简化展示，我们直接在用户态读取
    bpf_trace_printk("PID:%d Latency:%llu\\n", pid, delta);
    
    start.delete(&pid);
    return 0;
}
"""

# 2. 加载 BPF 程序并挂载到内核调度函数
b = BPF(text=bpf_source)
# 挂载到内核调度器相关函数
b.attach_tracepoint(tp="sched:sched_wakeup", fn_name="trace_enqueue")
b.attach_tracepoint(tp="sched:sched_switch", fn_name="trace_run")

print("正在实时监控容器延迟... 按下 Ctrl+C 停止")
try:
    with open("latency_data.csv", "w") as f:
        f.write("timestamp,pid,latency_ns\n")
        while True:
            # 读取内核输出的 trace 数据
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            if b"Latency" in msg:
                latency = msg.split(b":")[-1].strip()
                f.write(f"{ts},{pid},{latency.decode()}\n")
                print(f"进程 {pid} 调度延迟: {int(latency)/1000000:.2f} ms")
except KeyboardInterrupt:
    print("数据保存完毕。")