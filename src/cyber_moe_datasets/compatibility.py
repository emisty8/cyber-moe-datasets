"""Test the actual upstream tokenization function without importing MLX or executing a module."""

import ast
import hashlib
import json
from pathlib import Path


class ContractTokenizer:
    """Spy for input-format checks only. This is not a Qwen tokenizer."""

    def apply_chat_template(self, messages, *, tokenize, add_generation_prompt):
        if tokenize is not True or add_generation_prompt is not False:
            raise ValueError("unexpected upstream chat rendering behavior")
        return list(range(len(json.dumps(messages))))

    def encode(self, text):
        return list(range(len(text)))


def check_loader(loader: Path, dataset: Path) -> dict:
    payload = loader.read_bytes()
    tree = ast.parse(payload)
    functions = [
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_tokenize_entry"
    ]
    if len(functions) != 1:
        raise ValueError("loader contract not recognized; review installed version")
    # No arbitrary downloaded code execution: accept the reviewed function AST only.
    reviewed = Path(__file__).with_name("mlx_contract.json")
    expected = json.loads(reviewed.read_text(encoding="utf-8"))["function_ast_sha256"]
    actual = hashlib.sha256(ast.dump(functions[0], include_attributes=False).encode()).hexdigest()
    if actual != expected:
        raise ValueError("upstream function changed; review before contract test")
    namespace = {}
    module = ast.Module(body=functions, type_ignores=[])
    exec(compile(module, "reviewed_mlx_tokenization_contract", "exec"), namespace)
    rows = [json.loads(line) for line in dataset.read_text(encoding="utf-8").splitlines() if line]
    for row in rows:
        if not namespace["_tokenize_entry"](row, ContractTokenizer(), "content", 1000000):
            raise ValueError("empty calibration entry")
    return {
        "records_checked": len(rows),
        "format_contract": "passed",
        "loader_sha256": hashlib.sha256(payload).hexdigest(),
        "model_tokenization": "unverified",
        "mlx_execution": "unverified",
    }
