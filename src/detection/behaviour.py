"""Per-entity kill-chain progression.

Distinct from correlation/attack_reconstructor.py, which sequences stages
inside an already-correlated incident. This runs earlier and per entity, so a
single alert can say "this host is mid-chain".
"""

import math
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# The chain from the brief: login anomaly -> privilege escalation ->
# process execution -> lateral movement.
KILL_CHAIN: Tuple[str, ...] = (
    'login_anomaly',
    'privilege_escalation',
    'process_execution',
    'lateral_movement',
)

THREAT_TO_STAGE = {
    'Brute Force': 'login_anomaly',
    'Credential Compromise': 'login_anomaly',
    'Privilege Escalation': 'privilege_escalation',
    'Impact': 'process_execution',
    'Lateral Movement': 'lateral_movement',
}


@dataclass
class ChainState:
    stages: "OrderedDict[str, float]"  # stage -> sim_time first seen


class BehaviourTracker:
    """Tracks ordered kill-chain progress per entity, with time decay."""

    def __init__(self, half_life_seconds: float = 3600.0, max_entities: int = 50_000):
        self.half_life = half_life_seconds
        self.max_entities = max_entities
        self._states: "OrderedDict[str, ChainState]" = OrderedDict()

    def _state(self, entity: str) -> ChainState:
        state = self._states.get(entity)
        if state is None:
            state = ChainState(stages=OrderedDict())
            self._states[entity] = state
            if len(self._states) > self.max_entities:
                self._states.popitem(last=False)
        else:
            self._states.move_to_end(entity)
        return state

    def observe(self, entity: str, threat_type: Optional[str], sim_time: float) -> None:
        stage = THREAT_TO_STAGE.get(threat_type or '')
        if stage is None:
            return
        self._state(entity).stages.setdefault(stage, sim_time)

    def progress(self, entity: str, sim_time: float) -> Tuple[float, List[str]]:
        """Fraction of the chain observed in order, decayed by age."""
        state = self._states.get(entity)
        if state is None or not state.stages:
            return 0.0, []

        matched: List[str] = []
        weight = 0.0
        last_time = -math.inf
        for stage in KILL_CHAIN:
            seen = state.stages.get(stage)
            if seen is None or seen < last_time:
                continue  # order must hold
            age = max(sim_time - seen, 0.0)
            decay = 0.5 ** (age / self.half_life) if self.half_life > 0 else 1.0
            matched.append(stage)
            weight += decay
            last_time = seen

        return round(weight / len(KILL_CHAIN), 4), matched

    def entity_count(self) -> int:
        return len(self._states)
