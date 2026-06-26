# docker-compose example

A minimal portreach stack: one UI and two agents, with the UI discovering the
agents from a static list via `PORTREACH_AGENTS`.

```sh
docker compose up
```

Then open <http://localhost:8080/> and enter a `host:port` to check from both
agents. Or hit the JSON API:

```sh
curl 'http://localhost:8080/api/check?host=example.com&port=443'
```

Each agent reports a distinct `node` name (`agent1` / `agent2`) via the
`NODE_NAME` environment variable, so the result table shows one row per agent.

> Note: in this compose network the two agents share the bridge network and so
> egress from the same source — that is expected for a local demo. In real
> deployments each agent runs on a separate point (a Kubernetes node via the
> Helm chart, or a separate VM) so that each probes from its own network
> location.
