// frontend/src/hooks/useCVEData.ts

import { useState, useCallback, useEffect } from 'react';
import { cveApi, NodeStatus, ScanParams, StatsResponse } from '../services/api';

interface UseCVEDataReturn {
  nodes: NodeStatus[];
  stats: StatsResponse | null;
  isLoading: boolean;
  isConnected: boolean;
  error: string | null;
  scanCVEs: (params?: ScanParams) => Promise<void>;
  mitigate: (nodeId: string, action: string) => Promise<boolean>;
  refreshNodes: () => Promise<void>;
  clearError: () => void;
}

export function useCVEData(): UseCVEDataReturn {
  const [nodes, setNodes] = useState<NodeStatus[]>([]);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Check backend connection
  useEffect(() => {
    const checkConnection = async () => {
      const connected = await cveApi.healthCheck();
      setIsConnected(connected);
      
      if (connected) {
        const statsData = await cveApi.getStats();
        if (statsData) {
          setStats(statsData);
        }
      }
    };
    
    checkConnection();
    const interval = setInterval(checkConnection, 30000); // Check every 30s
    
    return () => clearInterval(interval);
  }, []);

  const scanCVEs = useCallback(async (params: ScanParams = {}) => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await cveApi.scanCVEs(params);

      if (response.success) {
        setNodes(response.nodes || []);
        
        // Refresh stats
        const statsResponse = await cveApi.getStats();
        if (statsResponse) {
          setStats(statsResponse);
        }
      } else {
        setError(response.error || 'Failed to scan CVEs');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setIsLoading(false);
    }
  }, []);

  const mitigate = useCallback(async (nodeId: string, action: string): Promise<boolean> => {
    try {
      const response = await cveApi.mitigate(nodeId, action);

      if (response.success) {
        // Update local state
        setNodes((prev) =>
          prev.map((node) =>
            node.id === nodeId
              ? {
                  ...node,
                  status: 'mitigated' as const,
                  risk: Math.max(5, node.risk * 0.1),
                }
              : node
          )
        );

        // Refresh stats
        const statsResponse = await cveApi.getStats();
        if (statsResponse) {
          setStats(statsResponse);
        }

        return true;
      } else {
        setError(response.error || 'Mitigation failed');
        return false;
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Mitigation failed');
      return false;
    }
  }, []);

  const refreshNodes = useCallback(async () => {
    setIsLoading(true);
    
    try {
      const response = await cveApi.getCascadeNodes({
        include_infrastructure: true,
      });
      
      setNodes(response.nodes);
      
      const statsResponse = await cveApi.getStats();
      if (statsResponse) {
        setStats(statsResponse);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to refresh');
    } finally {
      setIsLoading(false);
    }
  }, []);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  return {
    nodes,
    stats,
    isLoading,
    isConnected,
    error,
    scanCVEs,
    mitigate,
    refreshNodes,
    clearError,
  };
}

export default useCVEData;
