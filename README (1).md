# Automated SOAR Playbook — Shuffle Endpoint Containment Workflow

This educational project demonstrates a cautious event-to-SOAR workflow. A Python utility normalizes a security event, applies a small demonstration rule, and can send the decision to a Shuffle HTTPS webhook. Any actual endpoint isolation must be configured as a separate, reviewed action inside Shuffle with strict policy gates.

## Files

- `automated_soar_playbook.py` — event evaluator and optional Shuffle webhook notifier.
- `sample_security_event.json` — synthetic example event.
- `requirements.pdf` — hardware, software, functional, and safety requirements.
- `project_report.pdf` — report with the supplied Sandip University logo.
- `sandip_university_logo.png` — supplied logo asset.

## Requirements

- Python 3.10 or newer
- No third-party Python packages required
- A Shuffle instance and a workflow webhook, if webhook notification is enabled
- An authorized test environment and a synthetic event source

## Run locally

```bash
python automated_soar_playbook.py --input sample_security_event.json
```

This writes `soar_decision.json`. By default the script only evaluates and records a decision; it does not contact Shuffle or isolate an endpoint.

## Notify a Shuffle workflow

Configure a Shuffle webhook that accepts the event decision and includes validation, endpoint allowlisting, logging, and human approval for disruptive actions. Keep the webhook URL secret.

**Windows PowerShell**
```powershell
$env:SHUFFLE_WEBHOOK_URL = "https://your-shuffle-host.example/webhook/your-workflow-id"
python automated_soar_playbook.py --input sample_security_event.json --notify
```

**macOS/Linux**
```bash
export SHUFFLE_WEBHOOK_URL='https://your-shuffle-host.example/webhook/your-workflow-id'
python automated_soar_playbook.py --input sample_security_event.json --notify
```

Use HTTPS. Never commit webhook URLs, API tokens, or credentials to GitHub. The webhook URL format depends on your Shuffle deployment.

## Recommended Shuffle playbook gates

1. Validate event schema and source authenticity.
2. Deduplicate events and correlate endpoint identity.
3. Check endpoint against an explicit lab allowlist; never contain critical/shared infrastructure automatically.
4. Apply severity and confidence thresholds.
5. Require human approval for disruptive containment unless a formally approved policy says otherwise.
6. Execute endpoint isolation only through an authorized EDR/endpoint integration.
7. Record the action, result, and operator/workflow identity.
8. Provide a tested rollback/reconnect procedure and alert the incident-response team.

## Important limitations

- This script does not directly isolate endpoints.
- The demonstration rule is not a malware verdict and must be adapted to validated signals.
- A successful webhook request only means the endpoint accepted the HTTP request; it does not prove the workflow completed.
- Shuffle workflow nodes, credentials, and EDR integrations must be configured separately.
- Use only systems you own or are explicitly authorized to administer.

## License

Educational project template. Add an appropriate license before redistribution.
