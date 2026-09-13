import { api } from "./apiClient";
import type { Rule, RuleTestResult, RuleVersion } from "@/types/rules";

export function listRules(): Promise<Rule[]> {
  return api.get<Rule[]>("/rules");
}

export function getRule(ruleKey: string): Promise<Rule> {
  return api.get<Rule>(`/rules/${ruleKey}`);
}

export function setRuleStatus(ruleKey: string, status: string): Promise<Rule> {
  return api.post<Rule>(`/rules/${ruleKey}/status`, { status });
}

export function listRuleVersions(ruleKey: string): Promise<RuleVersion[]> {
  return api.get<RuleVersion[]>(`/rules/${ruleKey}/versions`);
}

export function testRule(definitionYaml: string, event: Record<string, unknown>): Promise<RuleTestResult> {
  return api.post<RuleTestResult>("/rules/test", { definition_yaml: definitionYaml, event });
}
