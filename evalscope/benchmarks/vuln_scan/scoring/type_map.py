"""vuln_type 归一化。

图灵平台的 vuln_type 大小写/中英/分隔符混杂（如 `idor`/`IDOR`/`越权访问`/
`authorization-bypass`/`Broken Access Control`），无法直接字符串比较。
本模块把任意写法归一到一组规范类型（kebab-case 小写），供 finding 与 GT 双侧统一匹配。

规范类型尽量对齐常见 CWE 命名；用户在 GT 中也应使用这些规范类型（或在此扩展 ALIASES）。
"""
from __future__ import annotations

# 规范类型集合（用于校验/展示）
CANONICAL_TYPES = {
    "path-traversal", "sql-injection", "command-injection", "xss",
    "idor", "broken-access-control", "deserialization", "mass-assignment",
    "ssrf", "xxe", "open-redirect", "csrf", "sensitive-data-exposure",
    "unvalidated-redirect", "file-upload", "ldap-injection", "xpath-injection",
    "hardcoded-credentials", "log-injection", "template-injection",
}

# 别名（已清洗形式）→ 规范类型。覆盖 fake_turing 实测类型 + 常见中英变体。
ALIASES: dict[str, str] = {
    # path traversal (CWE-22)
    "path-traversal": "path-traversal",
    "pathtraversal": "path-traversal",
    "directory-traversal": "path-traversal",
    "arbitrary-file-read": "path-traversal",
    "arbitrary-file-reads": "path-traversal",
    "任意文件读取": "path-traversal",
    "路径穿越": "path-traversal",
    "路径遍历": "path-traversal",
    "目录遍历": "path-traversal",
    # sql injection (CWE-89)
    "sql-injection": "sql-injection",
    "sqlinjection": "sql-injection",
    "sqli": "sql-injection",
    "sql注入": "sql-injection",
    # command injection (CWE-77/94)
    "command-injection": "command-injection",
    "commandinjection": "command-injection",
    "os-command-injection": "command-injection",
    "code-injection": "command-injection",
    "rce": "command-injection",
    "远程代码执行": "command-injection",
    "命令注入": "command-injection",
    # xss (CWE-79)
    "xss": "xss",
    "cross-site-scripting": "xss",
    "stored-xss": "xss",
    "reflected-xss": "xss",
    "存储型xss": "xss",
    "反射型xss": "xss",
    # idor (CWE-639)
    "idor": "idor",
    "idor-horizontal": "idor",
    "insecure-direct-object-reference": "idor",
    "不安全的直接对象引用": "idor",
    # broken access control (CWE-284/285/286)
    "broken-access-control": "broken-access-control",
    "authorization-bypass": "broken-access-control",
    "auth-bypass": "broken-access-control",
    "access-control": "broken-access-control",
    "privilege-escalation": "broken-access-control",
    "越权": "broken-access-control",
    "越权访问": "broken-access-control",
    "垂直越权": "broken-access-control",
    "水平越权": "broken-access-control",
    "权限绕过": "broken-access-control",
    "访问控制缺失": "broken-access-control",
    # deserialization (CWE-502)
    "deserialization": "deserialization",
    "insecure-deserialization": "deserialization",
    "反序列化": "deserialization",
    "不安全反序列化": "deserialization",
    # mass assignment (CWE-915)
    "mass-assignment": "mass-assignment",
    "批量赋值": "mass-assignment",
    # ssrf (CWE-918)
    "ssrf": "ssrf",
    "server-side-request-forgery": "ssrf",
    "服务端请求伪造": "ssrf",
    # xxe (CWE-611)
    "xxe": "xxe",
    "xml-external-entity": "xxe",
    # open redirect (CWE-601)
    "open-redirect": "open-redirect",
    "unvalidated-redirect": "unvalidated-redirect",
    "重定向": "open-redirect",
    # csrf (CWE-352)
    "csrf": "csrf",
    "cross-site-request-forgery": "csrf",
    # sensitive data
    "sensitive-data-exposure": "sensitive-data-exposure",
    "information-disclosure": "sensitive-data-exposure",
    "敏感信息泄露": "sensitive-data-exposure",
    "信息泄露": "sensitive-data-exposure",
    # file upload
    "file-upload": "file-upload",
    "unrestricted-file-upload": "file-upload",
    "任意文件上传": "file-upload",
    # hardcode
    "hardcoded-credentials": "hardcoded-credentials",
    "hardcoded-secrets": "hardcoded-credentials",
    "硬编码凭据": "hardcoded-credentials",
    # template injection
    "template-injection": "template-injection",
    "ssti": "template-injection",
}


def _clean(raw: str) -> str:
    """清洗：小写、统一分隔符、去括号。"""
    s = raw.strip().lower()
    s = s.replace("_", "-").replace(" ", "-")
    for ch in "()[]（）/\\,'\"":
        s = s.replace(ch, "-")
    # 折叠多余连字符
    while "--" in s:
        s = s.replace("--", "-")
    return s.strip("-")


def normalize(raw: str | None) -> str:
    """把任意 vuln_type 写法归一到规范类型。

    未命中 ALIASES 时返回清洗后的原值（不丢失，可能成为新的规范类型）。
    """
    if not raw:
        return "unknown"
    cleaned = _clean(raw)
    return ALIASES.get(cleaned, cleaned)
