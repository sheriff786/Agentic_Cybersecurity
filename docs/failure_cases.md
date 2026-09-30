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

We report **detection-layer recall per attack type** and **end-to-end attack
success rate with vs without the tool gate** in `eval/` specifically so that
"detection fails sometimes, but containment still holds" is demonstrated
with numbers, not just asserted.
