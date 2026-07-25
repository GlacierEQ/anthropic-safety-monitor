# Issue Contract — `anthropic-safety-monitor`

## Pain
Tool-use agents need policy deny for dangerous actions.

## Claim
Safety policy blocks disallowed tool patterns.

## Proof
```bash
python3 job-app/helix/proofs/proof_safety_monitor.py
```

## Done when
Proof exits 0. Architecture (strand/integrity/helix) is **not** a substitute for this proof.

## Anti-claim
Not Anthropic production safety stack.
