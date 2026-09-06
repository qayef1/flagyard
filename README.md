# FlagYard Host Solver

`flagyard-solve` automates the local workflow for a FlagYard event challenge:

1. Authenticate with FlagYard.
2. Download challenge attachments.
3. Start or reuse the challenge instance.
4. Run Codex on the host in automatic mode or an interactive TUI.
5. Validate and optionally submit a `BHFlagY{...}` flag.
6. Stop an instance that the solver started unless asked to keep it.

## Installation

```bash
python3 -m pip install -r requirements.txt
install -Dm755 flagyard_solve.py ~/.local/bin/flagyard-solve
```

The solver reads FlagYard credentials from environment variables or from the
`env` object in `~/.binarypilot/cli-config.json`:

```bash
export FLAGYARD_USERNAME='your-email@example.com'
export FLAGYARD_PASSWORD='your-password'
```

Codex CLI must already be installed and authenticated.

## Usage

Run the complete workflow automatically:

```bash
flagyard-solve 'https://flagyard.com/events/EVENT_ID/challenges/CHALLENGE_ID'
```

Open an interactive Codex TUI with host access and automatic approval bypass:

```bash
flagyard-solve 'https://flagyard.com/events/EVENT_ID/challenges/CHALLENGE_ID' \
  --interactive
```

Select another model and reasoning effort:

```bash
flagyard-solve 'CHALLENGE_URL' \
  --interactive \
  --model gpt-6-astra \
  --effort xhigh
```

Useful options:

```text
--prepare-only   Download attachments without starting or solving
--no-submit      Recover the flag without submitting it
--keep-instance  Leave the challenge instance running
--instruction    Add operator guidance for the solver
```

Run `flagyard-solve --help` for the complete CLI reference.
