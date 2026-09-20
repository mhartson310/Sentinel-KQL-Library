# Contributing

## Found a false positive I didn't document?

Open an issue with:
- The rule ID
- What fired
- Why it was benign
- What exclusion fixed it (if you found one)

FP reports are the most valuable contribution here. The tuning notes are the product.

## Want a rule that doesn't exist?

Open an issue with the scenario in plain language. Describe what you're trying to catch and what data you have. No KQL required.

## Submitting a rule

Follow the format in any existing rule file. Every rule needs:

- Metadata block (severity, MITRE tactic + technique, required table, suggested frequency)
- What it detects, in plain language
- The KQL, tested
- Tuning notes — what someone must change before production
- False positive table
- Response guidance

A rule without tuning notes will not be merged. That's the whole point of this repo.

## Style

- Table names and operators as they appear in the product
- Comment any threshold a user must change
- Prefer per-entity baselining over static thresholds where the data supports it
- Say when a query is expensive to run
