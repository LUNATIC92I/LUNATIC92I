import { api } from "./apiClient";
import type { AppUser } from "@/types/users";

export function listUsers(): Promise<AppUser[]> {
  return api.get<AppUser[]>("/users");
}

export function listRoleCatalog(): Promise<{ roles: string[] }> {
  return api.get<{ roles: string[] }>("/users/roles");
}

export function createUser(payload: {
  email: string;
  full_name: string;
  password: string;
  role: string;
}): Promise<AppUser> {
  return api.post<AppUser>("/users", payload);
}

export function updateUser(id: string, payload: { is_active?: boolean; role?: string }): Promise<AppUser> {
  return api.patch<AppUser>(`/users/${id}`, payload);
}
