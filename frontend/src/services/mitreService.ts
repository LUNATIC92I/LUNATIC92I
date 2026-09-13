import { api } from "./apiClient";
import type { Coverage } from "@/types/mitre";

export function getCoverage(): Promise<Coverage> {
  return api.get<Coverage>("/mitre/coverage");
}
