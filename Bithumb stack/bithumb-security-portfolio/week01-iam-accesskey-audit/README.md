# week01-iam-accesskey-audit

간단한 IAM Access Key 탐지 및 위험도 분류 PoC입니다.

Usage:

```bash
python src/scanner.py --input data/sample_iam_keys.json --out reports/scan_results.json --report reports/day01_report.md
```

생성된 리포트는 `reports/` 폴더에 저장됩니다.
