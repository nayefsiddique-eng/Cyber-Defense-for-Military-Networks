const risk = (value) => Number(value ?? 0);
const pct = (value) => Math.round(Number(value ?? 0) * (Number(value ?? 0) <= 1 ? 100 : 1));

export function adaptIncident(raw, index = 0) {
  const chain = raw.attack_chain || [];
  return {
    ...raw,
    id: raw.ui_id || raw.incident_id || `INC-${index + 1}`,
    sourceId: raw.incident_id,
    stage: raw.current_stage || chain.at(-1)?.stage || 'Unknown',
    risk: risk(raw.risk_score),
    confidence: pct(raw.prediction_confidence),
    assets: raw.affected_assets || [],
    techniques: chain.map(x => x.mitre_id).filter(Boolean),
    next: raw.predicted_next_stage || 'No prediction',
    evidence: raw.evidence || [],
    chain,
    graph: raw.attack_graph || { nodes: [], edges: [] },
    recommendations: raw.recommended_actions || [],
    factors: raw.risk_factors || {},
    blastRadius: raw.blast_radius || {},
  };
}

export function adaptAlert(raw) {
  return {
    ...raw,
    severity: String(raw.severity || 'INFO').toUpperCase(),
    score: pct(raw.score),
    confidence: pct(raw.confidence),
  };
}

export function adaptAsset(raw) {
  return {
    ...raw,
    id: raw.hostname || raw.asset_id,
    name: raw.hostname,
    segment: raw.network_segment,
    type: raw.asset_type,
    status: String(raw.status || 'unknown').toLowerCase(),
    ip: raw.ip,
    ports: raw.open_ports || [],
  };
}

export function adaptTelemetry(packet) {
  const event = packet?.event || packet || {};
  return {
    topic: packet?.topic,
    eventId: event.event_id || event.id || crypto.randomUUID(),
    timestamp: event.timestamp || new Date().toISOString(),
    asset: event.asset_id || event.hostname || event.destination_ip || 'UNKNOWN',
    sourceIp: event.source_ip,
    destinationIp: event.destination_ip,
    threatType: event.threat_type || event.event_type || 'Telemetry',
    severity: String(event.severity || 'INFO').toUpperCase(),
    evidence: event.evidence || event.message || '',
    raw: event,
  };
}
