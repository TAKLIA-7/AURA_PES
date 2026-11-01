# AURA API Reference

## 1. `AuraGateway`
The authoritative enforcement gateway.

```python
from aura.gateway import AuraGateway
from aura.models import RunContext, ToolRequest

gateway = AuraGateway(
    config_dir="config",
    db_path="aura.db",
    jsonl_path="audit.jsonl",
    jev_provider=None,  # Defaults to OpenRouter/Gemini/Mock based on env
)

# Synchronous request handler
result = gateway.handle(request: ToolRequest, run_ctx: RunContext) -> GatewayResult

# Asynchronous request handler
result = await gateway.handle_async(request: ToolRequest, run_ctx: RunContext) -> GatewayResult

# Execute an action previously approved by human operator
result = gateway.execute_approved(approval_id: str) -> GatewayResult
```

## 2. `AuraMultiAgentSystem`
LangGraph-powered multi-agent supervisor system with dynamic OpenRouter model switching.

```python
from aura.agent import AuraMultiAgentSystem, MODELS

# Initialize system (default model: D = deepseek/deepseek-chat)
mas = AuraMultiAgentSystem(model_key="D")

# Dynamically switch model
mas.set_model("B")  # switches to anthropic/claude-haiku-4.5
mas.set_model("D")  # switches to deepseek/deepseek-chat

# Execute user task
state = mas.run("Read document doc:public_report and summarize revenue")
print(state["final_response"])
```

## 3. `AuraStore` & `AuditLogger`
authoritative persistence and audit logger.

```python
# Verify cryptographic hash chain integrity
valid, error_msg = gateway.audit.verify_integrity()
assert valid is True

# Export database events to JSONL
count = gateway.audit.export_to_jsonl("export.jsonl")
```

