"use client";

import { useCallback, useEffect, useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";

interface CheckResult {
  status: "healthy" | "unhealthy" | "error" | "timedout" | "cancelled";
  response_time?: number;
  critical: boolean;
  error?: string;
  details?: Record<string, unknown>;
}

interface HealthResponse {
  status: "healthy" | "unhealthy";
  timestamp: string;
  checks: Record<string, CheckResult>;
}

export default function Home() {
  const [healthData, setHealthData] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHealth = useCallback(async (showToast = false) => {
    try {
      setLoading(true);
      setError(null);

      if (showToast) {
        toast.loading("Refreshing health status...", {
          id: "health-refresh",
        });
      }

      const response = await fetch("/api/health");

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      setHealthData(data);

      if (showToast) {
        toast.success("Health status updated", {
          id: "health-refresh",
          description: `System is ${data.status}`,
        });
      }
    } catch (err) {
      const errorMessage =
        err instanceof Error ? err.message : "Failed to fetch health data";
      setError(errorMessage);

      if (showToast) {
        toast.error("Failed to refresh health status", {
          id: "health-refresh",
          description: errorMessage,
          action: {
            label: "Retry",
            onClick: () => fetchHealth(true),
          },
        });
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 30000);
    return () => clearInterval(interval);
  }, [fetchHealth]);

  if (loading && !healthData) {
    return (
      <div className="container mx-auto p-8">
        <h1 className="text-3xl font-bold mb-8">CleanBoard Health Dashboard</h1>
        <Card className="p-6">
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <Skeleton className="h-4 w-[250px]" />
              <Skeleton className="h-4 w-[100px]" />
            </div>
            <div className="space-y-2">
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-[80%]" />
            </div>
          </div>
        </Card>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container mx-auto p-8">
        <h1 className="text-3xl font-bold mb-8">CleanBoard Health Dashboard</h1>
        <Card className="p-6 border-red-200 bg-red-50">
          <div className="flex items-center">
            <div className="w-3 h-3 bg-red-500 rounded-full mr-3"></div>
            <div>
              <p className="font-semibold text-red-800">Connection Error</p>
              <p className="text-sm text-red-600">{error}</p>
            </div>
          </div>
          <Button
            onClick={() => fetchHealth(true)}
            variant="destructive"
            className="mt-4"
          >
            Retry
          </Button>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-8">
      <h1 className="text-3xl font-bold mb-8">CleanBoard Health Dashboard</h1>

      <div className="mb-6">
        <Card
          className={`p-6 ${healthData?.status === "healthy" ? "border-green-200 bg-green-50" : "border-red-200 bg-red-50"}`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <div
                className={`w-4 h-4 rounded-full mr-3 ${healthData?.status === "healthy" ? "bg-green-500" : "bg-red-500"}`}
              ></div>
              <div>
                <h2 className="text-xl font-semibold">Overall System Status</h2>
                <Badge
                  variant={
                    healthData?.status === "healthy" ? "default" : "destructive"
                  }
                  className="mt-1"
                >
                  {healthData?.status}
                </Badge>
              </div>
            </div>
            <div className="text-sm text-gray-500">
              Last updated:{" "}
              {healthData?.timestamp
                ? new Date(healthData.timestamp).toLocaleString()
                : "Unknown"}
            </div>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {healthData?.checks &&
          Object.entries(healthData.checks).map(([checkName, result]) => (
            <Card
              key={checkName}
              className={`p-6 ${
                result.status === "healthy"
                  ? "border-green-200 bg-green-50"
                  : result.status === "unhealthy"
                    ? "border-yellow-200 bg-yellow-50"
                    : "border-red-200 bg-red-50"
              }`}
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center">
                  <div
                    className={`w-3 h-3 rounded-full mr-3 ${
                      result.status === "healthy"
                        ? "bg-green-500"
                        : result.status === "unhealthy"
                          ? "bg-yellow-500"
                          : "bg-red-500"
                    }`}
                  ></div>
                  <h3 className="font-semibold capitalize">{checkName}</h3>
                </div>
                {result.critical && (
                  <Badge variant="destructive">Critical</Badge>
                )}
              </div>

              <div className="space-y-2">
                <div className="flex justify-between items-center text-sm">
                  <span>Status:</span>
                  <Badge
                    variant={
                      result.status === "healthy"
                        ? "default"
                        : result.status === "unhealthy"
                          ? "secondary"
                          : "destructive"
                    }
                    className="text-xs"
                  >
                    {result.status}
                  </Badge>
                </div>

                {result.response_time && (
                  <div className="flex justify-between text-sm">
                    <span>Response Time:</span>
                    <span>{result.response_time.toFixed(3)}s</span>
                  </div>
                )}

                {result.error && (
                  <div className="text-sm">
                    <span className="font-medium text-red-700">Error:</span>
                    <p className="text-red-600 mt-1">{result.error}</p>
                  </div>
                )}

                {result.details && Object.keys(result.details).length > 0 && (
                  <div className="text-sm">
                    <span className="font-medium">Details:</span>
                    <div className="mt-1 text-gray-600">
                      {Object.entries(result.details).map(([key, value]) => (
                        <div key={key} className="flex justify-between">
                          <span>{key}:</span>
                          <span>{String(value)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </Card>
          ))}
      </div>

      <div className="mt-8 text-center">
        <Button onClick={() => fetchHealth(true)} disabled={loading} size="lg">
          {loading ? "Refreshing..." : "Refresh Status"}
        </Button>
      </div>
    </div>
  );
}
