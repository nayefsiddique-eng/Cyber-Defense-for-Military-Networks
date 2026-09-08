# Backend integration

The React app expects these dashboard endpoints in addition to the existing FastAPI control-plane endpoints:

- `GET /api/v1/incidents`
- `GET /api/v1/incidents/{incident_id}`
- `GET /api/v1/alerts`
- `GET /api/v1/assets`
- `GET /api/v1/topology`
- `GET /api/v1/dashboard/snapshot`
- `POST /api/v1/response/simulate`

Copy `backend_patch/src/api/dashboard.py` into the repository at `src/api/dashboard.py`, then add:

```python
from src.api.dashboard import router as dashboard_router
app.include_router(dashboard_router)
```

to `src/api/main.py` after the FastAPI app is created.

The existing WebSocket `/ws/telemetry/live` is already consumed directly by the React service layer. The frontend also uses the existing simulation start/status/stop endpoints.
