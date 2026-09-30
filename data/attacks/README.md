# Attack set

One `.txt` file per case, named `<attack_type>__<short_id>.txt`, where
`attack_type` matches an `AttackType` value in `src/pif_firewall/attack_types.py`
(e.g. `instruction_override__001.txt`).

Include both hand-crafted cases and a held-out slice from a public prompt
injection dataset that was not used to tune the detectors, per the plan's
evaluation requirement.
