#!/usr/bin/env python3
import json
from datetime import datetime, timezone
from pathlib import Path
import argparse

DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"


def parse_date(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, DATE_FMT).replace(tzinfo=timezone.utc)
    except Exception:
        return None


def days_since(d, ref=None):
    if d is None:
        return None
    if ref is None:
        ref = datetime.now(timezone.utc)
    return (ref - d).days


def permission_score(policies):
    # 단순 점수화: Admin 또는 와일드카드 => 100, PowerUser 70, 기타 매니지드 높은 권한 60, ReadOnly 10
    if not policies:
        return 0
    pset = set(policies)
    if "AdministratorAccess" in pset or "*" in pset:
        return 100
    if "PowerUserAccess" in pset:
        return 70
    high = {"AmazonS3FullAccess", "EC2FullAccess", "IAMFullAccess"}
    if pset & high:
        return 80
    if any("ReadOnly" in p for p in pset):
        return 10
    return 30


def classify(entry, ref=None):
    create_dt = parse_date(entry.get("create_date"))
    last_used_dt = parse_date(entry.get("last_used_date"))
    active = entry.get("is_active", True)
    perms = entry.get("attached_policies", [])

    days_unused = None if last_used_dt is None else days_since(last_used_dt, ref)
    days_old = None if create_dt is None else days_since(create_dt, ref)
    pscore = permission_score(perms)

    # 위험도 산정 (단순 가중치)
    score = 0
    # 사용 여부/오래된 키 가중치
    if last_used_dt is None:
        score += 40
    elif days_unused > 90:
        score += 30
    elif days_unused > 30:
        score += 10

    # 생성 후 오래됨
    if days_old and days_old > 365:
        score += 10

    # 권한 가중치
    score += int(pscore / 10)

    # 비활성 키는 위험하지만 우선 조사대상
    if not active:
        score += 5

    if score >= 18:
        risk = "High"
    elif score >= 10:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "access_key_id": entry.get("access_key_id"),
        "user_name": entry.get("user_name"),
        "is_active": active,
        "attached_policies": perms,
        "days_since_last_use": days_unused,
        "days_since_create": days_old,
        "permission_score": pscore,
        "risk_score": score,
        "risk_level": risk,
    }


def load_keys(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_report(report, out_path: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def generate_markdown_summary(results, out_md: Path):
    lines = []
    now = datetime.now(timezone.utc).isoformat()
    lines.append(f"# IAM Access Key Scan Report\n")
    lines.append(f"Generated: {now}\n")
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for r in results:
        counts[r["risk_level"]] += 1

    lines.append(f"- Total keys: {len(results)}")
    lines.append(f"- High risk: {counts['High']}")
    lines.append(f"- Medium risk: {counts['Medium']}")
    lines.append(f"- Low risk: {counts['Low']}\n")

    lines.append("## Details\n")
    for r in results:
        lines.append(f"- `{r['access_key_id']}` ({r['user_name']}): {r['risk_level']} - score {r['risk_score']}")

    out_md.parent.mkdir(parents=True, exist_ok=True)
    with out_md.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description="IAM Access Key Inventory Scanner")
    parser.add_argument("--input", "-i", default="data/sample_iam_keys.json")
    parser.add_argument("--out", "-o", default="reports/scan_results.json")
    parser.add_argument("--report", "-r", default="reports/day01_report.md")
    args = parser.parse_args()

    base = Path(__file__).resolve().parents[1]
    input_path = Path(args.input)
    if not input_path.is_absolute():
        input_path = base / input_path

    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = base / out_path

    report_md = Path(args.report)
    if not report_md.is_absolute():
        report_md = base / report_md

    keys = load_keys(input_path)
    ref = datetime.now(timezone.utc)
    results = [classify(k, ref) for k in keys]

    save_report(results, out_path)
    generate_markdown_summary(results, report_md)

    print(f"Scan complete. Results saved to: {out_path}")
    print(f"Summary report: {report_md}")


if __name__ == '__main__':
    main()
