export interface AccessTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  mfa_required: boolean;
}

export interface CurrentUser {
  id: string;
  email: string;
  full_name: string;
  tenant_id: string;
  roles: string[];
  permissions: string[];
}

/** `permissions` on `CurrentUser` is `"resource:action"` strings — this is
 * the shape every RBAC-gated UI check (`can(user, "hunt", "execute")`)
 * reads, mirroring `app.auth.dependencies.AuthenticatedUser.has_permission`
 * on the backend so the same question is asked the same way on both sides
 * (spec §19's requirement that UI hiding is cosmetic, never the real gate —
 * the server re-checks every call regardless of what this returns). */
export function can(user: CurrentUser | null, resource: string, action: string): boolean {
  return user?.permissions.includes(`${resource}:${action}`) ?? false;
}
