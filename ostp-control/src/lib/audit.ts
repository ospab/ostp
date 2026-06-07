import { api } from './api';

export interface AuditLogEntry {
  id: string;
  time: string;
  eventEn: string;
  eventRu: string;
  success: boolean;
}

export async function getAuditLogs(): Promise<AuditLogEntry[]> {
  try {
    return await api.getAuditLogs();
  } catch (e) {
    console.error('Failed to get audit logs', e);
    return [];
  }
}

export async function addAuditLog(eventEn: string, eventRu: string, success: boolean) {
  try {
    await api.createAuditLog(eventEn, eventRu, success);
    window.dispatchEvent(new Event('ostp_audit_log_added'));
  } catch (e) {
    console.error('Failed to write audit log', e);
  }
}

export async function clearAuditLogs() {
  try {
    await api.clearAuditLogs();
    window.dispatchEvent(new Event('ostp_audit_log_added'));
  } catch (e) {
    console.error('Failed to clear audit logs', e);
  }
}
