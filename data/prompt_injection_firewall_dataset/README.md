# Prompt Injection Firewall — Multimodal Test Dataset

200 files total:
- 10 malicious + 10 benign for each source type
- PDF, HTML, Email, Markdown, Word, API response, OCR text, Source code, Image, Generic text
- 100 malicious + 100 benign

## Important
The malicious files are intentionally synthetic security-test fixtures. They contain prompt-injection-like instructions but do not execute commands or access real credentials.

## Recommended use
1. Run every file through the normalization layer.
2. Attach source/provenance metadata.
3. Run detection ensemble.
4. Compare predicted label with `manifest.csv`.
5. For malicious samples, compare `attack_type`.
6. Measure recall by source and attack type.
7. Measure benign false-positive rate.
8. Keep these files separate from training data when using them as a demo/held-out test set.

The `content` field in manifest.csv is the expected semantic text after extraction/OCR.
