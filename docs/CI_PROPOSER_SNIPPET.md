# CI snippet for proposer (apply to `.github/workflows/ci.yml`)

The PR push token lacked the `workflow` scope, so add these steps under the
validate job (after long-lived protection selftest):

```yaml
      - name: Constrained proposer selftest
        run: python examples/proposer_selftest.py

      - name: Proposer intent cohort (template)
        run: python examples/proposer_intent_cohort_selftest.py
```

Also acceptable as a follow-up commit once a token with `workflow` scope is available.
