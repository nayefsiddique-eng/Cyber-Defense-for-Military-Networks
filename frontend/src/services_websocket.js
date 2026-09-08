const API_BASE = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');
const WS_URL = import.meta.env.VITE_WS_URL || API_BASE.replace(/^http/, 'ws') + '/ws/telemetry/live';

export function connectTelemetry({ onEvent, onStatus }) {
  let socket;
  let stopped = false;
  let retry;

  const open = () => {
    if (stopped) return;
    onStatus?.('connecting');
    socket = new WebSocket(WS_URL);
    socket.onopen = () => onStatus?.('connected');
    socket.onmessage = (message) => {
      try { onEvent?.(JSON.parse(message.data)); } catch (e) { console.error('Invalid telemetry message', e); }
    };
    socket.onerror = () => onStatus?.('error');
    socket.onclose = () => {
      onStatus?.('disconnected');
      if (!stopped) retry = window.setTimeout(open, 2500);
    };
  };
  open();
  return () => {
    stopped = true;
    if (retry) clearTimeout(retry);
    socket?.close();
  };
}
