name: Fetch NVD Vulnerabilities

on:
  schedule:
    - cron: '0 */6 * * *'
  workflow_dispatch:

permissions:
  contents: write

jobs:
  fetch-nvd:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install requests python-dateutil

      - name: Fetch NVD CVE data
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
        run: python scripts/fetch_nvd.py

      - name: Commit updated data
        run: |
          git config --global user.name 'TIS Bot'
          git config --global user.email 'bot@threatintelspecialist.com'
          git add -A
          git diff --staged --quiet || git commit -m "chore: update NVD vulnerability data [$(date -u '+%Y-%m-%d %H:%M UTC')]"
          git push
