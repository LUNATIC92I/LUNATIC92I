import { api } from "./apiClient";

export interface Organization {
  id: string;
  name: string;
  slug: string;
  is_active: boolean;
}

export function getMyOrganization(): Promise<Organization> {
  return api.get<Organization>("/organizations/me");
}
