import { useState, useEffect, useCallback } from 'react';

export type CustodyLogEntry = {
  timestamp: string;
  action: string;
  actor: string;
  detail: string;
};

export type QuarantineItem = {
  id: string;
  name: string;
  path: string;
  date: string;
  source: string;
  hash: string;
  status: string;
  threatId?: string;
  size?: string;
  sizeBytes?: number;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  entropy?: number;
  quarantineReason?: string;
  mitreTechnique?: string;
  isolatedFilePath?: string;
  custodyLog?: CustodyLogEntry[];
};

export type UseQuarantineState = {
  items: QuarantineItem[];
  loading: boolean;
  error: string | null;
  vaultPath: string | null;
  lastVerified: string | null;
  addQuarantine: (item: {
    path: string;
    name?: string;
    source?: string;
    severity?: 'critical' | 'high' | 'medium' | 'low';
    reason?: string;
    threatId?: string;
    mitreTechnique?: string;
  }) => Promise<QuarantineItem | null>;
  restoreQuarantine: (id: string) => Promise<boolean>;
  purgeQuarantine: (id: string) => Promise<boolean>;
  verifyIntegrity: () => Promise<{ success: boolean; allSealsValid: boolean; totalVerified: number }>;
  setItems: React.Dispatch<React.SetStateAction<QuarantineItem[]>>;
  refetch: () => Promise<void>;
};

export const initialQuarantineSeed: QuarantineItem[] = [
  {
    id: 'q-1',
    name: 'invoice_viewer.exe',
    path: 'C:\\Users\\mira\\Downloads\\invoice_viewer.exe',
    date: 'Yesterday, 18:15:01',
    source: 'outlook.exe',
    hash: 'a4f8c2b1e7d903a5b6c8d7e4f1a2b3c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1',
    status: 'Quarantined',
    threatId: 'thr-1',
    size: '1.82 MB',
    severity: 'critical',
    entropy: 7.82,
    quarantineReason: 'Unsigned execution binary spawned encoded PowerShell payload.',
    mitreTechnique: 'T1204.002 - User Execution: Malicious File',
  },
  {
    id: 'q-2',
    name: '~stage_042.zip',
    path: 'C:\\Users\\mira\\AppData\\Local\\Temp\\~stage_042.zip',
    date: 'Today, 09:42:41',
    source: '7z.exe (PID 9104)',
    hash: '7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e',
    status: 'Quarantined',
    threatId: 'thr-2',
    size: '845 KB',
    severity: 'high',
    entropy: 7.94,
    quarantineReason: 'Compressed archive staging classified sensitive documents.',
    mitreTechnique: 'T1560.001 - Archive via Utility',
  },
  {
    id: 'q-3',
    name: 'rundll32 module handle',
    path: 'C:\\Windows\\System32\\lsass.exe',
    date: 'Today, 09:47:19',
    source: 'rundll32.exe',
    hash: 'd13b77a0c5e19f8b2e410e41f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5',
    status: 'Quarantined',
    threatId: 'thr-2',
    size: '68.0 KB',
    severity: 'critical',
    entropy: 7.15,
    quarantineReason: 'Protected memory handle request injected from rundll32.exe.',
    mitreTechnique: 'T1003.001 - OS Credential Dumping: LSASS Memory',
  },
];

export function useQuarantine(): UseQuarantineState {
  const [items, setItems] = useState<QuarantineItem[]>(initialQuarantineSeed);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [vaultPath, setVaultPath] = useState<string | null>(null);
  const [lastVerified, setLastVerified] = useState<string | null>(null);

  const fetchQuarantine = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/quarantine');
      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      const data = await res.json();
      if (data && Array.isArray(data.items) && data.items.length > 0) {
        setItems(data.items);
        setVaultPath(data.vaultPath || null);
        setLastVerified(data.lastVerified || null);
      }
      setError(null);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchQuarantine();
  }, [fetchQuarantine]);

  const addQuarantine = useCallback(
    async (item: {
      path: string;
      name?: string;
      source?: string;
      severity?: 'critical' | 'high' | 'medium' | 'low';
      reason?: string;
      threatId?: string;
      mitreTechnique?: string;
    }) => {
      try {
        const res = await fetch('/api/quarantine', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(item),
        });
        if (!res.ok) throw new Error(`Failed to isolate file (${res.status})`);
        const data = await res.json();
        if (data.item) {
          setItems((prev) => [data.item, ...prev.filter((i) => i.id !== data.item.id)]);
          return data.item;
        }
      } catch (err) {
        console.error('Failed to quarantine file to vault:', err);
      }
      return null;
    },
    []
  );

  const restoreQuarantine = useCallback(async (id: string) => {
    try {
      const res = await fetch(`/api/quarantine/${id}/restore`, { method: 'POST' });
      if (!res.ok) throw new Error(`Failed to restore item ${id}`);
      const data = await res.json();
      if (data.item) {
        setItems((prev) => prev.map((i) => (i.id === id ? data.item : i)));
        return true;
      }
    } catch (err) {
      console.error('Failed to restore quarantined file:', err);
    }
    return false;
  }, []);

  const purgeQuarantine = useCallback(async (id: string) => {
    try {
      const res = await fetch(`/api/quarantine/${id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error(`Failed to purge item ${id}`);
      setItems((prev) => prev.filter((i) => i.id !== id));
      return true;
    } catch (err) {
      console.error('Failed to purge quarantined file:', err);
    }
    return false;
  }, []);

  const verifyIntegrity = useCallback(async () => {
    try {
      const res = await fetch('/api/quarantine/verify', { method: 'POST' });
      if (!res.ok) throw new Error('Verification failed');
      const data = await res.json();
      setLastVerified(data.timestamp || new Date().toISOString());
      return data;
    } catch (err) {
      console.error('Failed to verify quarantine seals:', err);
      return { success: false, allSealsValid: false, totalVerified: 0 };
    }
  }, []);

  return {
    items,
    loading,
    error,
    vaultPath,
    lastVerified,
    addQuarantine,
    restoreQuarantine,
    purgeQuarantine,
    verifyIntegrity,
    setItems,
    refetch: fetchQuarantine,
  };
}
