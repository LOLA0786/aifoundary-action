# AIFoundary Guardrail Scan

Detect unsafe AI prompts and configurations directly in CI/CD.

## Basic Usage (Warn Mode)
```yaml
- uses: LOLA0786/aifoundary-action@v1.2
  with:
    scan-path: .
Enforce Mode
yaml
Copy code
- uses: LOLA0786/aifoundary-action@v1.2
  with:
    scan-path: .
    mode: enforce
PR Comments
yaml
Copy code
with:
  github-token: ${{ secrets.GITHUB_TOKEN }}
SARIF (Security Tab)
Automatically uploads aifoundary.sarif

Galani Export (Enterprise)
yaml
Copy code
with:
  enable-galani: true
  galani-endpoint: https://galani.yourdomain.com/ingest
