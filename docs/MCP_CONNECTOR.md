# The ATL MCP connector

A passive MCP server that **consumes** ATLP packages. It is the seam between an
agent stack you already run and data you are not willing to hand over.

## The inversion

The normal integration gives the agent a database credential and hopes the
prompt holds:

```
MCP host  ──(SELECT * FROM ...)──▶  your database
```

This connector runs the other way. The host asks for fields; a local boundary
decides; a sealed package comes back containing only what was allowed:

```
MCP host  ──propose──▶  ATL connector  ──loopback──▶  ATL Edge
                             │                            │
          ◀──sealed ATLP─────┘                            └──▶ local data
```

The node does not query Salesforce. It does not call OpenAI. It holds no
provider key. See `iva.md` §"Invariante de producto" — the invariant is tested
in CI, not asserted in a brochure.

## The tools — all three of them

| Tool | Does | Does not |
|---|---|---|
| `propose` | Turns a bounded intent into a schema-valid proposal, or refuses it | Execute, read, or touch data |
| `execute` | Submits an approved proposal; returns a sealed ATLP package or a refusal reason | Return rows, accept host-supplied rows |
| `open_package` | Opens a package with the **node key** and returns the projected rows + receipt | Accept the provisioning master key |

There is no `query`, no `sql`, no `search`, no `chat`, no `describe_schema`.
That is not an oversight and not a roadmap item. `scripts/check_mcp_surface.py`
fails CI if the list grows, and its `--self-test` injects a `query` tool to
prove the guard still bites.

## Configuration

Claude Desktop / any MCP host, `mcpServers` entry:

```json
{
  "mcpServers": {
    "atl-edge": {
      "command": "python",
      "args": ["src/mcp_server.py"],
      "cwd": "/opt/atl-edge",
      "env": {
        "PYTHONPATH": "/opt/atl-edge",
        "ATL_NODE_ID": "node-warehouse-01",
        "ATL_NODE_KEY_HEX": "<derived node key, NOT the master>",
        "ATL_PACKAGE_KEY_ID": "edge-v1",
        "ATL_CONSOLE_TOKEN": "<token from .atl/edge/console_token.txt>",
        "ATL_MCP_EDGE": "http://127.0.0.1:8790"
      }
    }
  }
}
```

Start the node first, serving the trade's catalogue:

```bash
ATL_CATALOG=inventory bash scripts/start_stack.sh
```

### Environment

| Variable | Required | Notes |
|---|---|---|
| `ATL_NODE_KEY_HEX` | yes | 32 bytes hex, derived per node. `open_package` refuses to run without it. |
| `ATL_MASTER_KEY_HEX` | **must be absent** | If present, the connector refuses to open anything. A connector holds the derived key only. |
| `ATL_NODE_ID` | yes | Must match the node that sealed. |
| `ATL_PACKAGE_KEY_ID` | yes | Must match the Edge sealing `key_id`. |
| `ATL_CONSOLE_TOKEN` | yes | Bearer token for the local Edge. |
| `ATL_MCP_EDGE` | no | Default `http://127.0.0.1:8790`. **Loopback only** — a remote host is refused at startup. |

## Two deliberate constraints

**Loopback pin.** `ATL_MCP_EDGE` must resolve to a loopback address. The adapter
is the one file in the connector that imports a transport, so it is also the one
place an outbound path could appear. Pointing it at a remote host is refused
rather than logged, because "the node initiates nothing outbound" has to be true
at runtime and not only in the tests.

**The host cannot supply rows.** `execute` refuses `records`, `rows`, `data`
and `payload` in its arguments. The host names a resource; the node reads it
from its own catalogue. A host that could pass rows would be choosing what the
boundary minimises, which is the single thing it must not control.

## Verifying it yourself

```bash
python scripts/check_mcp_surface.py --self-test   # the surface is closed
python src/mcp_server.py --selftest               # no Edge needed
python src/mcp_server.py --list-tools             # print the three schemas

# live, against a running node, over real stdio:
ATL_CATALOG=inventory bash scripts/start_stack.sh
PYTHONPATH=. python examples/mcp_connector_demo.py
```

The live demo asserts the outcome rather than narrating it: a legitimate request
for `sku, description, qty_on_hand` returns exactly those three fields, and
`unit_price_gbp`, `customer_id` and `country` are checked absent from the
plaintext the connector opens. Grabs for `customer_id` and `unit_price_gbp` come
back `403`. A destructive intent is refused at the proposer, before any read.

CI job: `mcp-connector`.

## What this is not

- Not multi-platform. One trade works end to end (inventory); breadth comes
  after, not instead.
- Not a Salesforce integration. The adapter is generic MCP; a Salesforce MCP
  client can consume it, but the node never calls Salesforce.
- Not an IAM layer for your database. It governs what leaves through *this*
  boundary. Anyone with direct database credentials still has them.
- Not a chat interface over your data, by construction.
