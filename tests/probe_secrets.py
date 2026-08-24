"""快速探针：验证 SECRET_PATTERNS 在关键边界上的行为。"""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from core.prefilter import SECRET_PATTERNS

CASES = [
    ("AWS AK", '"AKIAIOSFODNN7EXAMPLE"'),
    ("阿里云 AK", '"LTAI4Gxxxxxxxxxxxxxx"'),
    ("OpenAI key", '"sk-abcdef0123456789abcdef0123456789"'),
    ("GitHub token", '"ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"'),
    ("JWT", '"eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM.SflKxwRJSMeKKF2QT4f"'),
    ("generic pwd 双引号", '"password":"admin12345"'),
    ("generic pwd 单引号", "'token':'abcdef1234567890'"),
    ("generic pwd 反引号", "`secret`:`backtick12345`"),
    ("Slack token", '"xoxb-1234567890-abcdefghij"'),
    ("Stripe live key", '"sk_live_abcdef1234567890abcdef"'),
    ("mongodb 连接串", '"mongodb://root:s3cr3t@10.0.0.1:27017/db"'),
    ("Bearer token", '"Authorization":"Bearer ya29.abcdef1234567890"'),
    ("腾讯云 AK", '"AKIDxxxxxxxxxxxxxxxxxxxxx"'),
    ("私钥头", '-----BEGIN RSA PRIVATE KEY-----'),
]

def run():
    for desc, sample in CASES:
        hits = []
        for name, sev, pat in SECRET_PATTERNS:
            for m in pat.finditer(sample):
                hits.append((name, m.group(0)[:40]))
        if hits:
            print(f"[OK ] {desc}")
            for n, v in hits:
                print(f"      {n}: {v}")
        else:
            print(f"[GAP] {desc}  -> (no hit)")
        print()

if __name__ == "__main__":
    run()
