# Live-agent experiment

Runs a real LLM agent on 6 operations tasks x 4 variants (no injection, and
three prompt injections), records what it does, then replays every recorded
trajectory against all seven defenses over real mTLS.

## Run it (about 20-40 minutes, a few dollars of API usage)

```
pip install anthropic cryptography pyjwt          # or: pip install openai
cd authz_server && npm install && cd ..
for a in agent_a agent_b agent_c agent_ops authz_server; do python3 certs/generate_ca.py $a; done
python3 ztcomm/policy_store.py

export ANTHROPIC_API_KEY=...                       # your key
python3 agent_experiment/run_agents.py --provider anthropic --model claude-sonnet-5-5 --reps 5
python3 agent_experiment/replay.py agent_experiment/results/trajectories_anthropic_claude-sonnet-5-5.jsonl
```

Any OpenAI-compatible model works too, including a local one:

```
python3 agent_experiment/run_agents.py --provider openai --model gpt-4.1 --reps 5
python3 agent_experiment/run_agents.py --provider openai --base-url http://localhost:11434/v1 --model qwen2.5:14b --reps 5
```

Send back `agent_experiment/results/summary_*.json`. The `mock` provider is a
scripted stand-in for testing the pipeline only; never report its numbers.
