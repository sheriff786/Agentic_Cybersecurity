# Known failure cases (reported honestly, on purpose)

Judges reward honesty here — these are the attacks this firewall is expected
to miss, and why.

1. **Attack stays inside an allowed action.** E.g. a misleading but
   "legitimate-looking" summary, or an email sent to an internal address
   with manipulated content. The tool gate only catches "sensitive data +
   external destination" patterns backed by DLP labels; it cannot judge
   truthfulness of content that never leaves the trust boundary.
2. **DLP coverage gaps.** The gate can only flag data it has a label for
   (regex patterns for keys/emails/cards, path/tag rules). Sensitive data in
   a format not covered by a rule (e.g. a novel internal identifier scheme)
   will not be caught.
3. **Novel phrasing in the uncertain band.** Rule + embedding detectors are
   pattern-based; a sufficiently novel instruction phrasing that avoids
   known patterns and doesn't trip the LLM-judge band can pass as Allow.
4. **Exact provenance tracing is not attempted.** Taint tracking is
   session/turn-level, not exact span-to-tool-call lineage — an attacker
   could potentially "cool down" across turns to avoid the taint threshold.

5. **Path-name based sensitivity.** The gate blocks untrusted-origin reads of
   paths that *look* sensitive (`/secrets/`, `.env`, `*credentials*`, keys). A
   sensitive file with an innocent name is not caught by the read rule; it is
   only caught later if its contents match a DLP pattern or the secret registry
   when sent externally, or if the external send is reviewed.
6. **Benign instruction-like text is flagged.** Phrases such as "please ignore
   my previous email" or "from now on, always cc ..." match rules. Calibrated
   weights make a single such hit a quarantine (span redacted) instead of a
   block, but the flagged rate on such text is not zero. Report flagged and
   hard-blocked rates separately.
7. **Plain-language attacks evade detection by design of the test set.** The
   evasive scenarios contain no injection phrasing at all; only containment
   stops them. That is the thesis, and also a limit: containment only protects
   what the gate knows how to classify.

We report **detection-layer recall per attack type** and **end-to-end attack
success rate with vs without the tool gate** in `eval/` specifically so that
"detection fails sometimes, but containment still holds" is demonstrated
with numbers, not just asserted.
