"""FastAPI Control Plane for Cyber Defense Range."""

import asyncio
from typing import Dict, Any, List
from datetime import datetime, timezone
import uuid

from fastapi import FastAPI, BackgroundTasks, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from src.config import config
from src.api.models import (
    AttackScenarioRequest, SimulationControlRequest, SimulationStatus,
    SimulationState, PipelineHealth, AssetListResponse, AssetResponse,
    ScenarioType, FullSimulationRequest, ErrorResponse
)
from src.simulator.engine import CyberRangeSimulator
from src.simulator.topology import MilitaryTopologyBuilder
from src.pipeline.event_bus import create_event_bus, EventBus
from src.pipeline.store import create_store, TelemetryStore
from src.pipeline.normalizer import TelemetryNormalizer
from src.pipeline.store import StorageSink

app = FastAPI(
    title="Military Cyber Defense Telemetry Engine",
    version="1.0.0",
    description="Control plane for the digital twin cyber range and streaming pipeline."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global State
active_simulations: Dict[str, Dict[str, Any]] = {}
event_bus: EventBus = None
store: TelemetryStore = None
normalizer: TelemetryNormalizer = None
sink: StorageSink = None
start_time: datetime = datetime.now(timezone.utc)

@app.on_event("startup")
async def startup_event():
    global event_bus, store, normalizer, sink
    
    # Initialize Pipeline Components based on mode
    event_bus = create_event_bus(mode=config.MODE)
    store = create_store(mode=config.MODE, output_dir=config.TELEMETRY_OUTPUT_DIR)
    
    normalizer = TelemetryNormalizer(event_bus)
    sink = StorageSink(event_bus, store, config.BATCH_SIZE, config.FLUSH_INTERVAL_SECONDS)
    
    await event_bus.start()
    await store.start()
    await normalizer.start()
    await sink.start()

@app.on_event("shutdown")
async def shutdown_event():
    if sink: await sink.stop()
    if normalizer: await normalizer.stop()
    if store: await store.stop()
    if event_bus: await event_bus.stop()

# --- Simulation Execution Tasks ---

async def run_simulation_task(task_id: str, request: FullSimulationRequest):
    sim_data = active_simulations[task_id]
    try:
        simulator = CyberRangeSimulator(config, event_bus)
        sim_data["simulator"] = simulator
        
        # We start the simulation loop here
        # This will block until simulation duration is reached, generating events
        await simulator.start(request.duration_seconds)
        
        sim_data["state"] = SimulationState.COMPLETED
    except Exception as e:
        sim_data["state"] = SimulationState.FAILED
        sim_data["error"] = str(e)

# --- Endpoints ---

@app.post("/api/v1/simulation/start", response_model=SimulationStatus)
async def start_simulation(request: FullSimulationRequest, bg_tasks: BackgroundTasks):
    task_id = f"sim-{uuid.uuid4().hex[:8]}"
    
    active_simulations[task_id] = {
        "task_id": task_id,
        "state": SimulationState.RUNNING,
        "scenario_type": "full_range",
        "start_time": datetime.now(timezone.utc).isoformat(),
        "seed": request.seed,
        "simulator": None
    }
    
    bg_tasks.add_task(run_simulation_task, task_id, request)
    
    return get_sim_status(task_id)

@app.get("/api/v1/simulation/{task_id}/status", response_model=SimulationStatus)
async def get_simulation_status(task_id: str):
    return get_sim_status(task_id)

@app.post("/api/v1/simulation/{task_id}/stop")
async def stop_simulation(task_id: str):
    if task_id not in active_simulations:
        raise HTTPException(status_code=404, detail="Task not found")
        
    sim_data = active_simulations[task_id]
    if sim_data["simulator"]:
        await sim_data["simulator"].stop()
        
    sim_data["state"] = SimulationState.CANCELLED
    return {"status": "Cancelled", "task_id": task_id}

@app.get("/api/v1/pipeline/health", response_model=PipelineHealth)
async def pipeline_health():
    uptime = (datetime.now(timezone.utc) - start_time).total_seconds()
    
    eb_stats = event_bus.get_topic_stats() if hasattr(event_bus, 'get_topic_stats') else {}
    store_stats = store.get_stats() if hasattr(store, 'get_stats') else {}
    
    return PipelineHealth(
        status="healthy",
        mode=config.MODE,
        event_bus=eb_stats,
        normalizer=normalizer.stats if normalizer else {},
        store=store_stats,
        pcap_engine={},
        uptime_seconds=uptime
    )

@app.websocket("/ws/telemetry/live")
async def websocket_telemetry(websocket: WebSocket):
    await websocket.accept()
    
    # We create a simple queue to bridge the event bus to the websocket
    queue = asyncio.Queue()
    
    async def ws_callback(topic, key, value):
        await queue.put({"topic": topic, "event": value})
        
    group_id = f"ws-client-{uuid.uuid4().hex[:6]}"
    await event_bus.subscribe(["telemetry.alerts.correlation"], group_id, ws_callback)
    
    try:
        while True:
            data = await queue.get()
            await websocket.send_json(data)
    except WebSocketDisconnect:
        pass
    finally:
        # A more robust implementation would properly unsubscribe here
        pass

def get_sim_status(task_id: str) -> SimulationStatus:
    if task_id not in active_simulations:
        raise HTTPException(status_code=404, detail="Simulation not found")
        
    sim = active_simulations[task_id]
    stats = sim["simulator"].get_stats() if sim.get("simulator") else {}
    
    return SimulationStatus(
        task_id=task_id,
        state=sim["state"],
        scenario_type=sim["scenario_type"],
        events_generated=stats.get("events_generated", 0),
        events_normalized=normalizer.stats.get("events_normalized", 0) if normalizer else 0,
        events_stored=sink.stats.get("events_stored", 0) if sink else 0,
        start_time=sim["start_time"],
        elapsed_seconds=(datetime.now(timezone.utc) - datetime.fromisoformat(sim["start_time"])).total_seconds(),
        seed=sim["seed"],
        error_message=sim.get("error")
    )
