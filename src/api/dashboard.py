"""Dashboard integration endpoints for the React command centre."""
from pathlib import Path
import json
import tempfile
import os
from typing import Any, Dict
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from src.models.inventory import AssetInventory
from src.simulator.topology import MilitaryTopologyBuilder

router = APIRouter(prefix="/api/v1", tags=["dashboard"])
ROOT = Path(__file__).resolve().parents[2]
INCIDENTS_FILE = ROOT / "data" / "output" / "incidents.json"
ALERTS_FILE = ROOT / "data" / "alerts" / "mock_alerts.json"

def read_json(path):
    if not path.exists(): return []
    with path.open("r", encoding="utf-8") as f: return json.load(f)

def incident_view(item, index):
    out = dict(item)
    # Checked-in sample data currently reuses INC-001 three times.
    out["ui_id"] = f"{item.get('incident_id', 'INC')}-{index + 1:03d}"
    return out

class WhatIfRequest(BaseModel):
    incident_id: str
    action: str
    asset_id: str | None = None

@router.get("/incidents")
def incidents():
    data = read_json(INCIDENTS_FILE)
    return {"total": len(data), "incidents": [incident_view(x, i) for i, x in enumerate(data)]}

@router.get("/incidents/{incident_id}")
def incident(incident_id: str):
    data = read_json(INCIDENTS_FILE)
    for i, item in enumerate(data):
        if item.get("incident_id") == incident_id or f"{item.get('incident_id', 'INC')}-{i + 1:03d}" == incident_id:
            return incident_view(item, i)
    raise HTTPException(status_code=404, detail="Incident not found")

@router.get("/alerts")
def alerts():
    data = read_json(ALERTS_FILE)
    return {"total": len(data), "alerts": data}
@router.get("/assets")
def assets():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    try:
        inventory = AssetInventory(db_path)
        MilitaryTopologyBuilder().build(inventory)

        rows = []
        for a in inventory.get_all():
            rows.append({
                "asset_id": a.asset_id, "ip": a.ip, "mac_address": a.mac_address,
                "hostname": a.hostname, "asset_type": a.asset_type.value,
                "criticality": a.criticality.value, "network_segment": a.network_segment.value,
                "owner": a.owner, "os": a.os, "status": a.status.value,
                "open_ports": [s.port for s in a.services if s.is_open],
                "services": [{"port":s.port,"protocol":s.protocol,"service_name":s.service_name,"version":s.version,"is_open":s.is_open} for s in a.services],
            })
        return {"total": len(rows), "assets": rows}

    finally:
        try:
            os.remove(db_path)
        except OSError:
            pass

@router.get("/topology")
def topology():
    return {"segments":[
        {"id":"DMZ","label":"DMZ"},{"id":"ENTERPRISE","label":"NIPRNet / Enterprise"},
        {"id":"TACTICAL","label":"TOC / Tactical"},{"id":"CLASSIFIED","label":"SIPRNet / Classified"},
        {"id":"FIELD","label":"Tactical Edge / Field"},{"id":"SCADA","label":"SCADA / ICS"}],
        "firewall_rules":{"DMZ_TO_ENTERPRISE":[80,443,25],"ENTERPRISE_TO_TOC":["ALL"],"TOC_TO_CLASSIFIED":[22,1521],"FIELD_TO_TOC":["UDP_TELEMETRY"],"SCADA_TO_ENTERPRISE":["ONLY_HMI01"]}}

@router.get("/dashboard/snapshot")
def snapshot():
    inc = read_json(INCIDENTS_FILE); alerts_data = read_json(ALERTS_FILE)
    return {"incidents":[incident_view(x,i) for i,x in enumerate(inc)],"alerts":alerts_data,
            "summary":{"active_incidents":len(inc),"critical_incidents":sum(1 for x in inc if str(x.get("severity","")).upper()=="CRITICAL"),"compromised_assets":len({a for x in inc for a in x.get("affected_assets",[])}),"predicted_attacks":sum(1 for x in inc if x.get("predicted_next_stage"))}}

@router.post("/response/simulate")
def simulate_response(req: WhatIfRequest):
    data=read_json(INCIDENTS_FILE)
    target=next((x for x in data if x.get("incident_id")==req.incident_id),None)
    if not target: raise HTTPException(status_code=404, detail="Incident not found")
    base=float(target.get("risk_score",0)); action=req.action.lower()
    reduction=27.1 if "isolate" in action else 18.0 if ("block" in action or "restrict" in action) else 8.0 if "investigate" in action else 5.0
    after=max(0.0,round(base-reduction,2)); confidence=float(target.get("prediction_confidence",0))
    return {"incident_id":req.incident_id,"action":req.action,"asset_id":req.asset_id,"simulation_only":True,
            "before":{"risk_score":base,"prediction_confidence":confidence},
            "after":{"risk_score":after,"prediction_confidence":max(0.0,round(confidence-reduction/100,4))},"risk_reduction":round(base-after,2)}
