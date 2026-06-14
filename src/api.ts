import type { SecurityEvent, User, CurrentUser } from "./types";

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`/api${path}`, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers ?? {}),
    },
  });

  const body = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(body.error ?? `Request failed (${res.status})`);
  }

  return body as T;
}

export async function login(
  email: string,
  password: string
): Promise<{ user: { id: string; email: string; role: string } }> {
  return request("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function logout(): Promise<void> {
  await request("/auth/logout", { method: "POST" });
}

export async function me(): Promise<CurrentUser> {
  return request<CurrentUser>("/auth/me");
}

export async function getEvents(): Promise<SecurityEvent[]> {
  return request<SecurityEvent[]>("/events");
}

export async function getEvent(id: string): Promise<SecurityEvent> {
  return request<SecurityEvent>(`/events/${id}`);
}

export async function getUsers(): Promise<User[]> {
  return request<User[]>("/users");
}

export async function createUser(user: {
  email: string;
  password: string;
  role: string;
}): Promise<User> {
  return request<User>("/users", {
    method: "POST",
    body: JSON.stringify(user),
  });
}

export async function updateUser(
  id: string,
  data: { role?: string; status?: string }
): Promise<User> {
  return request<User>(`/users/${id}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export async function deleteUser(id: string): Promise<void> {
  await request(`/users/${id}`, { method: "DELETE" });
}
