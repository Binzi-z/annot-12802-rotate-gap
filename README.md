# 日志轮转缺口期的事件关联

日志按小时轮转，整点附近的事件会落在两个文件里。

```
logs/auth.log   860 行（合成，含 2 起真实事件）
labels.json     2 个标注事件
detector/detector.py  基线检测器
tests/          骨架测试
```

## Run

```bash
python -m pytest tests -q
python detector/detector.py logs/auth.log findings.json
# 跨轮转边界：把相邻两个小时的日志一起传入，最后一个参数是输出文件
python detector/detector.py logs/auth.log.1 logs/auth.log findings.json
```

检测器把所有输入文件合并到一条时间线上再做关联，跨文件的事件链不会断。
输出 `findings.json` 含 `findings`（rule、first_seen、last_seen、entities、
evidence——按时间排列、带文件名与行号的事件序列）与 `needs_review`
（拿不准的项，`missing` 字段写明缺什么证据）。

## 基线状态

`detector/detector.py` 对每条失败登录和每个请求各产出一条告警，不做任何关联：
不看失败之后有没有成功登录，不看同账号是否跨主机，也不看请求路径是否敏感。

## 标注事件

| kind | 说明 |
|---|---|
| `dns_tunnel` | DNS 隧道外传 |
| `webshell` | 上传后执行 webshell |

日志里另有故意放入的**良性相似流量**（少量失败后成功、被拒绝的少量探测），任何命中都算误报。
