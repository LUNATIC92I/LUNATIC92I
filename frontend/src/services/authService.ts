import { api, apiRequest } from "./apiClient";
import { setAccessToken } from "./tokenStore";
import type { AccessTokenResponse, CurrentUser } from "@/types/auth";

export interface LoginParams {
  organizationSlug: string;
  email: string;
  password: string;
  mfaCode?: string;
}

export async function login(params: LoginParams): Promise<AccessTokenResponse> {
  const body = await apiRequest<AccessTokenResponse>("/auth/login", {
    method: "POST",
    skipAuthRetry: true,
    body: {
      organization_slug: params.organizationSlug,
      email: params.email,
      password: params.password,
      mfa_code: params.mfaCode,
    },
  });
  setAccessToken(body.access_token);
  return body;
}

export async function logout(): Promise<void> {
  try {
    await apiRequest<void>("/auth/logout", { method: "POST", skipAuthRetry: true });
  } finally {
    setAccessToken(null);
  }
}

export function fetchCurrentUser(): Promise<CurrentUser> {
  return api.get<CurrentUser>("/users/me");
}

export interface RegisterOrganizationParams {
  organizationName: string;
  organizationSlug: string;
  adminEmail: string;
  adminPassword: string;
  adminFullName: string;
}

export function registerOrganization(
  params: RegisterOrganizationParams,
): Promise<{ organization_id: string; organization_slug: string; user_id: string }> {
  return apiRequest("/auth/register-organization", {
    method: "POST",
    skipAuthRetry: true,
    body: {
      organization_name: params.organizationName,
      organization_slug: params.organizationSlug,
      admin_email: params.adminEmail,
      admin_password: params.adminPassword,
      admin_full_name: params.adminFullName,
    },
  });
}
