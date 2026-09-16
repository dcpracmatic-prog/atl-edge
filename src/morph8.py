"""Python FFI for the deterministic MORPH-8 structural gate."""
from __future__ import annotations
import ctypes
import json
from pathlib import Path
from dataclasses import dataclass

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "build" / "libmorph8.so"

V_NAMES = {
    0: "empty", 1: "size", 2: "syntax", 3: "schema",
    4: "tool", 5: "action", 6: "causal", 7: "control",
}
R_NAMES = {0: "trim", 1: "fence", 2: "crlf"}

class _Decision(ctypes.Structure):
    _fields_ = [
        ("decision", ctypes.c_int),
        ("health", ctypes.c_double),
        ("energy", ctypes.c_double),
        ("violations", ctypes.c_uint32),
        ("state_mask", ctypes.c_uint32),
        ("structural_mask", ctypes.c_uint32),
        ("repairs", ctypes.c_uint32),
    ]

@dataclass(frozen=True)
class MorphResult:
    decision: str
    health: float
    energy: float
    violations: tuple[str, ...]
    state_mask: int
    structural_mask: int
    repairs: tuple[str, ...]
    text: str

class MorphGate:
    def __init__(self, library: Path = LIB):
        self.library = Path(library)
        if not self.library.exists():
            raise RuntimeError(f"MORPH library not built: {self.library}")
        self.lib = ctypes.CDLL(str(self.library))
        self.lib.morph_predigest.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.POINTER(_Decision),
        ]
        self.lib.morph_predigest.restype = ctypes.c_int
        self.lib.morph_version.restype = ctypes.c_char_p

    @property
    def version(self) -> str:
        return self.lib.morph_version().decode("utf-8")

    def process(self, text: str, policy: str) -> MorphResult:
        raw = text.encode("utf-8")
        pol = policy.encode("utf-8")
        cap = max(1, len(raw) + 1)
        buf = ctypes.create_string_buffer(cap)
        d = _Decision()
        rc = self.lib.morph_predigest(raw, len(raw), pol, len(pol), buf, cap, ctypes.byref(d))
        if rc != 0:
            raise RuntimeError(f"MORPH error {rc}")
        decision = ("REJECT", "ACCEPT", "REPAIR")[d.decision] if d.decision in (0,1,2) else "REJECT"
        violations = tuple(name for bit, name in V_NAMES.items() if d.violations & (1 << bit))
        repairs = tuple(name for bit, name in R_NAMES.items() if d.repairs & (1 << bit))
        return MorphResult(decision, d.health, d.energy, violations, d.state_mask, d.structural_mask, repairs, buf.value.decode("utf-8"))


def default_policy() -> str:
    return "\n".join([
        "allow_tool=lookup",
        "allow_tool=normalize",
        "allow_tool=validate",
        "allow_tool=publish",
        "allow_operation=read",
        "allow_operation=normalize",
        "allow_operation=validate",
        "allow_operation=publish",
        "deny_operation=delete",
        "deny_operation=drop",
        "deny_operation=truncate",
        "deny_action=delete",
        "require=tool",
        "deny_field=shell",
        "deny_field=exec",
        "deny_field=command",
    ])


def run_selftest() -> bool:
    gate = MorphGate()
    policy = default_policy()
    tests = [
        ("valid", '{"tool":"lookup","operation":"read","query":"test"}', "ACCEPT"),
        ("repair", '```json\n{"tool":"lookup","operation":"read","query":"test"}\n```', "REPAIR"),
        ("forbidden_action", '{"tool":"write","action":"delete"}', "REJECT"),
        ("unknown_tool", '{"tool":"launch_missiles"}', "REJECT"),
        ("causal_cycle", '{"tool":"lookup","steps":[{"id":"a","tool":"lookup","operation":"read","depends_on":["b"]},{"id":"b","tool":"validate","operation":"validate","depends_on":["a"]}]}', "REJECT"),
        ("command_without_denylist", '{"tool":"lookup","command":"rm -rf /"}', "REJECT"),
        ("no_tool_allowlist", '{"tool":"lookup"}', "REJECT"),
        ("deterministic_repeat", '{"tool":"lookup","operation":"read","query":"same"}', "ACCEPT"),
    ]
    ok = True
    for name, text, expected in tests:
        test_policy = "" if name == "no_tool_allowlist" else policy
        a = gate.process(text, test_policy)
        b = gate.process(text, test_policy)
        same = a == b
        passed = a.decision == expected and same
        print(f"{name}: {a.decision} health={a.health:.3f} mask={a.state_mask} structural={a.structural_mask} repairs={list(a.repairs)} {'PASS' if passed else 'FAIL'}")
        if not passed: ok = False
    print(f"MORPH selftest: {'PASS' if ok else 'FAIL'}")
    return ok
