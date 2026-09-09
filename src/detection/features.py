"""Windowed feature extraction from a stream of OCSF events.

Features attach to an *entity* (a user, a source IP, an asset), not to a single
event, because "is this suspicious?" is a question about behaviour over time.
One event can therefore update several entities.

Every entity yields the same fixed-length vector so the ML models get a stable
schema; features that do not apply to an entity kind are simply 0.
"""

import math
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple

# OCSF class_uid values produced by the normalizer.
AUTH = 3002
NETWORK = 4001
DNS = 4003
FINDING = 2001
PROCESS = 1007

FEATURE_NAMES: Tuple[str, ...] = (
    'failed_login_count',
    'login_frequency',
    'connection_frequency',
    'bytes_out',
    'unique_destinations',
    'port_entropy',
    'process_frequency',
    'login_time_deviation',
)

FAILED_LOGON_CODES = {4625, 4771}


@dataclass(frozen=True)
class EntityKey:
    kind: str  # 'user' | 'src_ip' | 'asset'
    value: str

    def __str__(self) -> str:
        return f"{self.kind}:{self.value}"


@dataclass
class Observation:
    """The minimum retained per event, to keep windows small."""
    sim_time: float
    class_uid: int
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    bytes_out: int = 0
    is_login: bool = False
    login_failed: bool = False
    is_process: bool = False
    username: Optional[str] = None


@dataclass
class FeatureVector:
    entity: EntityKey
    sim_time: float
    values: Dict[str, float]
    event: Dict[str, Any] = field(default_factory=dict)
    distinct_ports: int = 0
    distinct_failed_users: int = 0
    window_events: int = 0

    def as_list(self) -> List[float]:
        return [self.values[name] for name in FEATURE_NAMES]

    def __getattr__(self, item: str) -> float:
        # Convenience: fv.port_entropy
        values = self.__dict__.get('values') or {}
        if item in values:
            return values[item]
        raise AttributeError(item)


def shannon_entropy(counts: List[int]) -> float:
    """Shannon entropy in bits.

    Deliberately NOT normalised by log2(n): dividing by the number of distinct
    values makes 6 uniformly-hit ports and 40 uniformly-hit ports both score
    1.0, which erases the breadth signal that separates a port scan from an
    ordinary host. Raw bits grow with breadth (6 ports = 2.58, 40 = 5.32).
    """
    total = sum(counts)
    if total <= 0 or len(counts) <= 1:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


class HourBaseline:
    """Circular mean/std of login hour.

    Hour-of-day wraps, so a linear mean puts 23:00 and 01:00 12 hours apart.
    Directional statistics handle the wrap correctly.
    """

    __slots__ = ('n', 'sin_sum', 'cos_sum')

    def __init__(self) -> None:
        self.n = 0
        self.sin_sum = 0.0
        self.cos_sum = 0.0

    def deviation(self, hour: float, min_observations: int) -> float:
        if self.n < min_observations:
            return 0.0
        s, c = self.sin_sum / self.n, self.cos_sum / self.n
        r = math.hypot(s, c)
        if r < 1e-9:
            return 0.0
        mean = math.atan2(s, c)
        sigma = math.sqrt(max(-2.0 * math.log(min(r, 1.0)), 1e-4))
        theta = 2 * math.pi * hour / 24.0
        distance = abs(math.atan2(math.sin(theta - mean), math.cos(theta - mean)))
        return distance / (sigma + 1e-6)

    def update(self, hour: float) -> None:
        theta = 2 * math.pi * hour / 24.0
        self.sin_sum += math.sin(theta)
        self.cos_sum += math.cos(theta)
        self.n += 1


class FeatureStore:
    """Maintains per-entity sliding windows and computes feature vectors."""

    def __init__(
        self,
        window_seconds: float = 300.0,
        max_entities: int = 50_000,
        min_baseline_observations: int = 5,
        max_window_events: int = 2000,
    ) -> None:
        self.window_seconds = window_seconds
        self.max_entities = max_entities
        self.min_baseline_observations = min_baseline_observations
        self.max_window_events = max_window_events
        self._windows: "OrderedDict[EntityKey, Deque[Observation]]" = OrderedDict()
        self._baselines: Dict[str, HourBaseline] = {}

    # --- event decoding -------------------------------------------------
    @staticmethod
    def _endpoint(event: Dict[str, Any], side: str) -> Dict[str, Any]:
        return event.get(side) or {}

    def _entities(self, event: Dict[str, Any]) -> List[EntityKey]:
        keys: List[EntityKey] = []
        actor = event.get('actor') or {}
        user = actor.get('user_name') or actor.get('user_id')
        if user:
            keys.append(EntityKey('user', str(user)))

        src_ip = self._endpoint(event, 'src_endpoint').get('ip')
        if src_ip:
            keys.append(EntityKey('src_ip', str(src_ip)))

        device = event.get('device') or {}
        host = device.get('hostname') or self._endpoint(event, 'src_endpoint').get('hostname')
        if host:
            keys.append(EntityKey('asset', str(host)))
        return keys

    def _observation(self, event: Dict[str, Any]) -> Observation:
        class_uid = int(event.get('class_uid') or 0)
        dst = self._endpoint(event, 'dst_endpoint')
        status = event.get('status')
        code = event.get('event_code')
        failed = status == 'failure' or (code in FAILED_LOGON_CODES)
        return Observation(
            sim_time=float(event.get('sim_time') or 0.0),
            class_uid=class_uid,
            dst_ip=dst.get('ip'),
            dst_port=dst.get('port'),
            bytes_out=int(event.get('bytes_out') or 0),
            is_login=class_uid == AUTH,
            login_failed=class_uid == AUTH and failed,
            is_process=class_uid == PROCESS,
            username=(event.get('actor') or {}).get('user_name'),
        )

    # --- windows --------------------------------------------------------
    def _window(self, key: EntityKey) -> Deque[Observation]:
        window = self._windows.get(key)
        if window is None:
            window = deque(maxlen=self.max_window_events)
            self._windows[key] = window
            if len(self._windows) > self.max_entities:
                self._windows.popitem(last=False)  # evict least-recently-used
        else:
            self._windows.move_to_end(key)
        return window

    def _evict(self, window: Deque[Observation], now: float) -> None:
        cutoff = now - self.window_seconds
        while window and window[0].sim_time < cutoff:
            window.popleft()

    # --- features -------------------------------------------------------
    def _compute(self, key: EntityKey, window: Deque[Observation],
                 event: Dict[str, Any], hour: float) -> FeatureVector:
        minutes = max(self.window_seconds / 60.0, 1e-6)
        ports = Counter(o.dst_port for o in window if o.dst_port is not None)
        destinations = {o.dst_ip for o in window if o.dst_ip}

        values = {
            'failed_login_count': float(sum(1 for o in window if o.login_failed)),
            'login_frequency': sum(1 for o in window if o.is_login) / minutes,
            'connection_frequency': sum(1 for o in window if o.class_uid in (NETWORK, DNS)) / minutes,
            'bytes_out': float(sum(o.bytes_out for o in window)),
            'unique_destinations': float(len(destinations)),
            'port_entropy': shannon_entropy(list(ports.values())),
            'process_frequency': sum(1 for o in window if o.is_process) / minutes,
            'login_time_deviation': 0.0,
        }

        if key.kind == 'user':
            baseline = self._baselines.setdefault(key.value, HourBaseline())
            if window and window[-1].is_login:
                # Deviation is measured before the baseline absorbs this login.
                values['login_time_deviation'] = baseline.deviation(
                    hour, self.min_baseline_observations)
                baseline.update(hour)

        return FeatureVector(
            entity=key,
            sim_time=float(event.get('sim_time') or 0.0),
            values=values,
            event=event,
            distinct_ports=len(ports),
            distinct_failed_users=len({o.username for o in window
                                       if o.login_failed and o.username}),
            window_events=len(window),
        )

    def observe(self, event: Dict[str, Any]) -> List[FeatureVector]:
        """Ingest one OCSF event, returning a vector per touched entity."""
        observation = self._observation(event)
        hour = _hour_of_day(event)
        vectors: List[FeatureVector] = []

        for key in self._entities(event):
            window = self._window(key)
            window.append(observation)
            self._evict(window, observation.sim_time)
            vectors.append(self._compute(key, window, event, hour))
        return vectors

    def entity_count(self) -> int:
        return len(self._windows)


def _hour_of_day(event: Dict[str, Any]) -> float:
    timestamp = event.get('time')
    if isinstance(timestamp, str) and len(timestamp) >= 16:
        try:
            return int(timestamp[11:13]) + int(timestamp[14:16]) / 60.0
        except ValueError:
            pass
    return (float(event.get('sim_time') or 0.0) % 86400.0) / 3600.0
