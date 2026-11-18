# GSB Bugfix Task
## 题面
后台IP白名单校验模块可被绕过：IPv4/IPv6混合解析异常、CIDR计算错误、未处理ip映射、信任X‑Forwarded‑For未校验来源、未截断多余ip段；acl/ip_acl.py 是核心，tests/test_ip_whitelist.py 15个红。要修的是：统一ip版本解析、修正CIDR匹配逻辑、仅可信代理读取XFF、丢弃多余ip字段、规范化ip文本。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：漏洞检测与攻防
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：无外部依赖
