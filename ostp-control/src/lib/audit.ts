export interface AuditLogEntry {
  id: string;
  time: string;
  eventEn: string;
  eventRu: string;
  success: boolean;
}

const AUDIT_LOG_KEY = 'ostp_audit_logs';

export function getAuditLogs(): AuditLogEntry[] {
  try {
    const raw = localStorage.getItem(AUDIT_LOG_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function addAuditLog(eventEn: string, eventRu: string, success: boolean) {
  try {
    const logs = getAuditLogs();
    const newEntry: AuditLogEntry = {
      id: Math.random().toString(36).substring(2, 9),
      time: new Date().toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      eventEn,
      eventRu,
      success,
    };
    // Keep last 100 logs
    const updated = [newEntry, ...logs].slice(0, 100);
    localStorage.setItem(AUDIT_LOG_KEY, JSON.stringify(updated));
    // Dispatch custom event to notify listeners
    window.dispatchEvent(new Event('ostp_audit_log_added'));
  } catch (e) {
    console.error('Failed to write audit log', e);
  }
}

export function clearAuditLogs() {
  localStorage.removeItem(AUDIT_LOG_KEY);
  window.dispatchEvent(new Event('ostp_audit_log_added'));
}
