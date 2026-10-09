/**
 * usePredictions — React hook for consuming ARGUS PS-24 Attack Path Predictions.
 *
 * Interfaces with GET /api/predictions to retrieve deterministic, forward-looking,
 * uncertainty-quantified attack-stage predictions derived from correlated incidents
 * and live EventHub detections.
 *
 * Predictions are explicitly flagged as `isPredicted: true` and are MITRE ATT&CK anchored.
 */

import { useCallback, useEffect, useState } from 'react';

export type AttackStage =
  | 'INITIAL_ACCESS'
  | 'EXECUTION'
  | 'PERSISTENCE'
  | 'PRIVILEGE_ESCALATION'
  | 'DEFENSE_EVASION'
  | 'LATERAL_MOVEMENT'
  | 'COLLECTION'
  | 'EXFILTRATION'
  | 'IMPACT';

export type PredictionBasis =
  | 'RULE_CORRELATION'
  | 'TEMPORAL_PATTERN'
  | 'BEHAVIORAL_PATTERN';

export type PredictionUncertainty = 'LOW' | 'MEDIUM' | 'HIGH';

export type StagePrediction = {
  stage: AttackStage;
  mitreId?: string;
  confidence: number;
  uncertainty: PredictionUncertainty;
  evidenceRefs: string[];
  explanation: string;
  isPredicted: true;
  basis: PredictionBasis;
};

export type PredictionResponse = {
  predictions: StagePrediction[];
  generatedAt: string;
  incidentCount: number;
};

export type UsePredictionsResult = {
  predictions: StagePrediction[];
  generatedAt: string | null;
  incidentCount: number;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
};

const POLL_INTERVAL_MS = 3000;

export function usePredictions(): UsePredictionsResult {
  const [predictions, setPredictions] = useState<StagePrediction[]>([]);
  const [generatedAt, setGeneratedAt] = useState<string | null>(null);
  const [incidentCount, setIncidentCount] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPredictions = useCallback(async () => {
    try {
      const res = await fetch('/api/predictions');
      if (res.ok) {
        const data: PredictionResponse = await res.json();
        setPredictions(Array.isArray(data.predictions) ? data.predictions : []);
        setGeneratedAt(data.generatedAt || new Date().toISOString());
        setIncidentCount(data.incidentCount ?? 0);
        setError(null);
      } else {
        setError(`Predictions request failed with HTTP ${res.status}`);
      }
    } catch (err: any) {
      setError(err?.message || 'Unable to connect to prediction engine');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPredictions();
    const timer = setInterval(fetchPredictions, POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [fetchPredictions]);

  return {
    predictions,
    generatedAt,
    incidentCount,
    loading,
    error,
    refresh: fetchPredictions,
  };
}
