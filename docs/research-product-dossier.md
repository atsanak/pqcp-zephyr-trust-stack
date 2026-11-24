# Research And Product Dossier

`scripts/generate_research_product_dossier.py` creates maintainer-facing
analysis from the live repository and, when available, a generated release
evidence pack. It is a planning artifact, not a certification statement.

The generator reads the claim catalog, asset trace map, policy, profile,
evidence-quality rules, benchmark campaign configuration, and selected release
artifacts. It writes:

- `research_product_dossier.json`
- `research_hardening_dossier.md`
- `product_strategy_brief.md`

Example:

```bash
python3 scripts/generate_research_product_dossier.py \
  --module-path . \
  --release-output /tmp/pqcp-release-pack \
  --output-root /tmp/pqcp-dossier \
  --tag v1.0.0
```

The generated Markdown names real claim IDs, asset IDs, artifact paths, and
SHA-256 hashes where a release pack is provided. This keeps the analysis tied
to executable evidence rather than generic positioning text.

