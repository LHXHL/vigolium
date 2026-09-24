'use client';

import { useState, useMemo } from 'react';
import { RefreshCw, Terminal, Filter, Layers } from 'lucide-react';
import { useScans, useDeleteScan, useStopScan, usePauseScan, useResumeScan, useScanLogs, useAgentSessions } from '@/api/hooks';
import { useToast } from '@/contexts/ToastContext';
import type { ScansQueryParams, Scan, ScanLog, ScanLogsQueryParams, AgentSession, AgentSessionsQueryParams } from '@/api/types';
import { agentStatusTone, type AgentStatusTone } from '@/api/types';
import { formatDuration, truncate } from '@/lib/formatters';
import { formatDate } from '@/lib/formatters';

const HISTORY_PAGE_SIZE = 5;

const LOG_LEVELS = ['all', 'trace', 'info', 'warn', 'error'] as const;
const LOG_PHASES = ['all', 'config', 'heuristics', 'harvest', 'spidering', 'discovery', 'seed', 'spa', 'sast', 'audit'] as const;

function StatusBadge({ status }: { status: string }) {
  const color =
    status === 'running' ? '#00b368' :
    status === 'paused' ? '#b8860b' :
    status === 'completed' ? '#0078c8' :
    status === 'failed' ? '#e34e1c' :
    '#708e8e';
  return (
    <span className="text-xs font-bold uppercase" style={{ color }}>
      {status}
    </span>
  );
}

function tryParseJson(s: string): Record<string, unknown> | null {
  try { return JSON.parse(s); } catch { return null; }
}

function ScanActions({ scan, onStop, onDelete, onPause, onResume }: { scan: Scan; onStop: (uuid: string) => void; onDelete: (uuid: string) => void; onPause: (uuid: string) => void; onResume: (uuid: string) => void }) {
  const [confirmDel, setConfirmDel] = useState(false);

  return (
    <div className="flex items-center gap-1">
      {scan.status === 'running' && (
        <>
          <button
            onClick={(e) => { e.stopPropagation(); onPause(scan.uuid); }}
            className="text-[10px] text-[#b8860b] hover:underline"
          >
            [pause]
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); onStop(scan.uuid); }}
            className="text-[10px] text-[#e34e1c] hover:underline"
          >
            [stop]
          </button>
        </>
      )}
      {scan.status === 'paused' && (
        <>
          <button
            onClick={(e) => { e.stopPropagation(); onResume(scan.uuid); }}
            className="text-[10px] text-[#00b368] hover:underline"
          >
            [resume]
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); onStop(scan.uuid); }}
            className="text-[10px] text-[#e34e1c] hover:underline"
          >
            [stop]
          </button>
        </>
      )}
      {!confirmDel ? (
        <button
          onClick={(e) => { e.stopPropagation(); setConfirmDel(true); }}
          className="text-[10px] text-[#708e8e] hover:text-[#e34e1c]"
        >
          [del]
        </button>
      ) : (
        <span className="flex items-center gap-1">
          <button
            onClick={(e) => { e.stopPropagation(); onDelete(scan.uuid); setConfirmDel(false); }}
            className="text-[10px] text-[#e34e1c] hover:underline"
          >
            [confirm]
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); setConfirmDel(false); }}
            className="text-[10px] text-[#708e8e] hover:underline"
          >
            [cancel]
          </button>
        </span>
      )}
    </div>
  );
}

const STATUS_TONE_COLOR: Record<AgentStatusTone, string> = {
  ok: '#00b368', warn: '#b8860b', fail: '#e34e1c', running: '#0078c8', idle: '#708e8e',
};

function SessionStatusBadge({ status }: { status: string }) {
  const color = STATUS_TONE_COLOR[agentStatusTone(status)];
  return <span className="text-xs font-bold" style={{ color }}>{status}</span>;
}

export default function ScanHistoryTable() {
  const [historyParams, setHistoryParams] = useState<ScansQueryParams>({ limit: HISTORY_PAGE_SIZE, offset: 0 });
  const [sessionsParams, setSessionsParams] = useState<AgentSessionsQueryParams>({ limit: HISTORY_PAGE_SIZE, offset: 0 });

  const { data: scansData, isLoading: scansLoading, refetch, isFetching } = useScans(historyParams);
  const { data: sessionsData } = useAgentSessions(sessionsParams);
  const deleteScan = useDeleteScan();
  const stopScan = useStopScan();
  const pauseScan = usePauseScan();
  const resumeScan = useResumeScan();
  const { toast } = useToast();

  const historyPage = Math.floor((historyParams.offset || 0) / HISTORY_PAGE_SIZE) + 1;
  const historyTotalPages = Math.ceil((scansData?.total || 0) / HISTORY_PAGE_SIZE);

  const sessionsPage = Math.floor((sessionsParams.offset || 0) / HISTORY_PAGE_SIZE) + 1;
  const sessionsTotalPages = Math.ceil((sessionsData?.total || 0) / HISTORY_PAGE_SIZE);

  return (
    <div className="space-y-2">
      {/* Scan History */}
      <div className="border border-[#bbc3c4] bg-[#f6edda] overflow-hidden">
        <div className="px-3 py-1.5 border-b border-[#bbc3c4]">
          <div className="flex items-center gap-1.5">
            <span className="text-[#0078c8] text-xs font-bold">SCAN HISTORY</span>
            <button onClick={() => refetch()} className="text-[#708e8e] hover:text-[#0078c8] transition-colors" title="Refresh">
              <RefreshCw className={`w-3 h-3 ${isFetching ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#bbc3c4]">
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">STATUS</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">NAME</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">MODE / SOURCE</th>
                <th className="text-right px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">FINDINGS</th>
                <th className="text-right px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">PROCESSED</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">STARTED</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {scansLoading && (
                Array.from({ length: HISTORY_PAGE_SIZE }).map((_, i) => (
                  <tr key={`sk-${i}`} className="border-b border-[#bbc3c4]/50">
                    <td className="px-3 py-1.5"><span className="v-skeleton inline-block h-3 w-16" /></td>
                    <td className="px-3 py-1.5"><span className="v-skeleton inline-block h-3 w-32" /></td>
                    <td className="px-3 py-1.5"><span className="v-skeleton inline-block h-3 w-24" /></td>
                    <td className="px-3 py-1.5 text-right"><span className="v-skeleton inline-block h-3 w-8" /></td>
                    <td className="px-3 py-1.5 text-right"><span className="v-skeleton inline-block h-3 w-10" /></td>
                    <td className="px-3 py-1.5"><span className="v-skeleton inline-block h-3 w-20" /></td>
                    <td className="px-3 py-1.5"><span className="v-skeleton inline-block h-3 w-12" /></td>
                  </tr>
                ))
              )}
              {!scansLoading && (!scansData?.data || scansData.data.length === 0) && (
                <tr>
                  <td colSpan={7} className="px-3 py-4 text-center text-[#bbc3c4] v-fade-in">no scans</td>
                </tr>
              )}
              {scansData?.data?.map((scan) => (
                <tr
                  key={scan.uuid}
                  className="border-b border-[#bbc3c4]/50 hover:bg-[#ede4d1] transition-colors v-fade-in"
                >
                  <td className="px-3 py-1.5"><StatusBadge status={scan.status} /></td>
                  <td className="px-3 py-1.5 text-[#005661]">{scan.name || scan.uuid.slice(0, 8)}</td>
                  <td className="px-3 py-1.5 text-[#708e8e]">{[scan.scan_mode, scan.scan_source].filter(Boolean).join(' / ') || '-'}</td>
                  <td className="px-3 py-1.5 text-right text-[#005661]">{scan.total_findings}</td>
                  <td className="px-3 py-1.5 text-right text-[#005661]">{scan.processed_count}</td>
                  <td className="px-3 py-1.5 text-[#708e8e]">{formatDate(scan.started_at)}</td>
                  <td className="px-3 py-1.5">
                    <ScanActions
                      scan={scan}
                      onStop={(uuid) => stopScan.mutate(uuid, { onError: (err) => toast((err as Error).message, 'error') })}
                      onDelete={(uuid) => deleteScan.mutate(uuid, { onError: (err) => toast((err as Error).message, 'error') })}
                      onPause={(uuid) => pauseScan.mutate(uuid, { onError: (err) => toast((err as Error).message, 'error') })}
                      onResume={(uuid) => resumeScan.mutate(uuid, { onError: (err) => toast((err as Error).message, 'error') })}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {(scansData?.total || 0) > HISTORY_PAGE_SIZE && (
          <div className="flex items-center justify-between px-3 py-1 border-t border-[#bbc3c4] text-xs text-[#708e8e]">
            <span>
              {(historyParams.offset || 0) + 1}-{Math.min((historyParams.offset || 0) + HISTORY_PAGE_SIZE, scansData?.total || 0)}/{scansData?.total || 0}
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setHistoryParams((p) => ({ ...p, offset: ((p.offset || 0) - HISTORY_PAGE_SIZE) }))}
                disabled={historyPage <= 1}
                className="hover:text-[#0078c8] disabled:opacity-30 px-1"
              >
                {'<'}
              </button>
              <span className="px-1">{historyPage}/{historyTotalPages}</span>
              <button
                onClick={() => setHistoryParams((p) => ({ ...p, offset: ((p.offset || 0) + HISTORY_PAGE_SIZE) }))}
                disabled={historyPage >= historyTotalPages}
                className="hover:text-[#0078c8] disabled:opacity-30 px-1"
              >
                {'>'}
              </button>
            </div>
          </div>
        )}

        {(deleteScan.isError || stopScan.isError || pauseScan.isError || resumeScan.isError) && (
          <div className="px-3 py-1 text-xs text-[#e34e1c]">
            error: {((deleteScan.error || stopScan.error || pauseScan.error || resumeScan.error) as Error)?.message}
          </div>
        )}
      </div>

      {/* Agent Sessions */}
      <div className="border border-[#bbc3c4] bg-[#f6edda] overflow-hidden">
        <div className="px-3 py-1.5 border-b border-[#bbc3c4]">
          <span className="text-[#0078c8] text-xs font-bold inline-flex items-center gap-1.5">
            <Layers className="w-3 h-3" />AGENT SESSIONS
            {sessionsData?.total != null && <span className="text-[#708e8e] font-normal ml-1">({sessionsData.total})</span>}
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#bbc3c4]">
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">STATUS</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">UUID</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">MODE</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">AGENT</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">TARGET</th>
                <th className="text-right px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">FINDINGS</th>
                <th className="text-right px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">SAVED</th>
                <th className="text-right px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">DURATION</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">COMPLETED</th>
              </tr>
            </thead>
            <tbody>
              {!sessionsData ? (
                Array.from({ length: HISTORY_PAGE_SIZE }).map((_, i) => (
                  <tr key={`sess-sk-${i}`} className="border-b border-[#bbc3c4]/50">
                    <td className="px-3 py-1.5"><span className="v-skeleton inline-block h-3 w-16" /></td>
                    <td className="px-3 py-1.5"><span className="v-skeleton inline-block h-3 w-16" /></td>
                    <td className="px-3 py-1.5"><span className="v-skeleton inline-block h-3 w-12" /></td>
                    <td className="px-3 py-1.5"><span className="v-skeleton inline-block h-3 w-20" /></td>
                    <td className="px-3 py-1.5"><span className="v-skeleton inline-block h-3 w-32" /></td>
                    <td className="px-3 py-1.5 text-right"><span className="v-skeleton inline-block h-3 w-8" /></td>
                    <td className="px-3 py-1.5 text-right"><span className="v-skeleton inline-block h-3 w-8" /></td>
                    <td className="px-3 py-1.5 text-right"><span className="v-skeleton inline-block h-3 w-10" /></td>
                    <td className="px-3 py-1.5"><span className="v-skeleton inline-block h-3 w-20" /></td>
                  </tr>
                ))
              ) : sessionsData.data && sessionsData.data.length > 0 ? (
                sessionsData.data.map((s: AgentSession) => (
                  <tr key={s.uuid} className="border-b border-[#bbc3c4]/50 hover:bg-[#ede4d1] transition-colors">
                    <td className="px-3 py-1.5"><SessionStatusBadge status={s.status} /></td>
                    <td className="px-3 py-1.5 text-[#0078c8] font-mono">{s.uuid.slice(0, 8)}</td>
                    <td className="px-3 py-1.5 text-[#708e8e]">{s.mode}</td>
                    <td className="px-3 py-1.5 text-[#005661]">{s.agent_name || '—'}</td>
                    <td className="px-3 py-1.5 text-[#005661]">{s.target_url ? truncate(s.target_url, 40) : '—'}</td>
                    <td className="px-3 py-1.5 text-right text-[#005661]">{s.finding_count}</td>
                    <td className="px-3 py-1.5 text-right text-[#00b368]">{s.saved_count}</td>
                    <td className="px-3 py-1.5 text-right text-[#005661]">{formatDuration(s.duration_ms)}</td>
                    <td className="px-3 py-1.5 text-[#708e8e]">{s.completed_at ? formatDate(s.completed_at) : '—'}</td>
                  </tr>
                ))
              ) : (
                <tr><td colSpan={9} className="px-3 py-4 text-center text-[#bbc3c4]">no sessions</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {(sessionsData?.total || 0) > HISTORY_PAGE_SIZE && (
          <div className="flex items-center justify-between px-3 py-1 border-t border-[#bbc3c4] text-xs text-[#708e8e]">
            <span>
              {(sessionsParams.offset || 0) + 1}-{Math.min((sessionsParams.offset || 0) + HISTORY_PAGE_SIZE, sessionsData?.total || 0)}/{sessionsData?.total || 0}
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setSessionsParams((p) => ({ ...p, offset: ((p.offset || 0) - HISTORY_PAGE_SIZE) }))}
                disabled={sessionsPage <= 1}
                className="hover:text-[#0078c8] disabled:opacity-30 px-1"
              >
                {'<'}
              </button>
              <span className="px-1">{sessionsPage}/{sessionsTotalPages}</span>
              <button
                onClick={() => setSessionsParams((p) => ({ ...p, offset: ((p.offset || 0) + HISTORY_PAGE_SIZE) }))}
                disabled={sessionsPage >= sessionsTotalPages}
                className="hover:text-[#0078c8] disabled:opacity-30 px-1"
              >
                {'>'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
