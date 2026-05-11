import {
  AxiosError,
  AxiosInstance,
  HttpStatusCode,
  InternalAxiosRequestConfig,
} from "axios";

import { createSession } from "@/app/sessions";

import { DataResponse } from "./types";

export class CustomError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = "APIError";
    Object.setPrototypeOf(this, CustomError.prototype);
  }
}

type RefreshPayload = {
  access_token: string;
  refresh_token: string;
  anonymous_user: "yes" | "no";
  user_roles: { id: string; name: string }[];
  business_id?: string;
};
let refreshPromise: Promise<DataResponse<RefreshPayload>> | null = null;
function isRefreshRequest(config?: InternalAxiosRequestConfig) {
  const url = config?.url ?? "";
  return url.includes("/api/auth/refresh") || url.includes("/auth/refresh");
}
async function refreshAccessTokenClient(): Promise<
  DataResponse<RefreshPayload>
> {
  try {
    const res = await fetch("/api/auth/refresh", {
      method: "POST",
      credentials: "include",
    });
    const json = (await res.json()) as DataResponse<RefreshPayload>;
    if (!res.ok) return { data: null, error: json?.error ?? "Refresh failed" };
    return json;
  } catch {
    return { data: null, error: "Network error" };
  }
}
function getServerErrorMessageSync(
  status: number,
  error: AxiosError,
  details: unknown,
): string {
  if (details && typeof details === "object" && "error" in details) {
    return String(details.error);
  }
  switch (status) {
    case HttpStatusCode.Unauthorized:
      return "Unauthorized: You don't have required access.";
    case HttpStatusCode.BadRequest:
      return "Bad Request: Verify the input.";
    case HttpStatusCode.Forbidden:
      return "Forbidden: Access denied.";
    case HttpStatusCode.NotFound:
      return "Not Found: The requested resource doesn't exist.";
    case HttpStatusCode.InternalServerError:
      return "Internal Server Error: Something went wrong on the server.";
    case HttpStatusCode.ServiceUnavailable:
      return "Service Unavailable: Please try again later.";
    default:
      return error.message || "Request failed";
  }
}

/** Axios types `get()` as a wide union; HTTP headers in practice are string or string[]. */
function headerValueToString(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (Array.isArray(value) && typeof value[0] === "string") return value[0];
  return undefined;
}

function existingForwardedForHeader(
  config: InternalAxiosRequestConfig,
): string | undefined {
  const headers = config.headers;
  if (!headers) return undefined;
  if (typeof headers.get === "function") {
    return (
      headerValueToString(headers.get("x-forwarded-for")) ||
      headerValueToString(headers.get("X-Forwarded-For"))
    );
  }
  const plain = headers as Record<string, string | undefined>;
  return plain["x-forwarded-for"] || plain["X-Forwarded-For"];
}

export const setupInterceptors = (axiosInstance: AxiosInstance) => {
  axiosInstance.interceptors.request.use(async (config) => {
    const forwardedAlreadySet = Boolean(existingForwardedForHeader(config));
    if (typeof window !== "undefined") {
      const cookieMap = Object.fromEntries(
        document.cookie.split("; ").map((pair) => pair.split("=")),
      );
      if (!forwardedAlreadySet) {
        const clientIp = cookieMap["x-client-ip"];
        if (clientIp) {
          config.headers["X-Forwarded-For"] = clientIp;
        }
      }
      const clientProto = cookieMap["x-client-proto"];
      if (clientProto) {
        config.headers["X-Forwarded-Proto"] = clientProto;
      }
    } else {
      const nextHeaders = await import("next/headers");
      const cookieStore = await nextHeaders.cookies();
      let incoming: Awaited<
        ReturnType<(typeof nextHeaders)["headers"]>
      > | null = null;
      try {
        incoming = await nextHeaders.headers();
      } catch {
        incoming = null;
      }

      if (!forwardedAlreadySet) {
        let clientIp = cookieStore.get("x-client-ip")?.value;
        if (!clientIp && incoming) {
          const fromForwarded =
            incoming.get("x-forwarded-for")?.split(",")[0]?.trim() || "";
          clientIp =
            process.env.NEXT_PUBLIC_SENTRY_ENVIRONMENT === "local"
              ? process?.env?.LOCAL_IP?.trim() || fromForwarded
              : fromForwarded;
        }
        if (clientIp) {
          config.headers["X-Forwarded-For"] = clientIp;
        }
      }

      const clientProto =
        cookieStore.get("x-client-proto")?.value ||
        incoming?.get("x-forwarded-proto")?.trim() ||
        undefined;
      if (clientProto) {
        config.headers["X-Forwarded-Proto"] = clientProto;
      }

      const clientUa =
        cookieStore.get("x-client-ua")?.value ||
        incoming?.get("user-agent")?.trim() ||
        undefined;
      if (clientUa) {
        config.headers["User-Agent"] = clientUa;
      }
    }
    return config;
  });
  axiosInstance.interceptors.response.use(
    (response) => response,
    async (error: AxiosError) => {
      const status = error.response?.status ?? 0;
      const details = error.response?.data ?? null;
      const originalConfig = error.config as
        | (InternalAxiosRequestConfig & {
            _retry?: boolean;
          })
        | undefined;
      if (
        status === HttpStatusCode.Unauthorized &&
        originalConfig &&
        !originalConfig._retry &&
        !isRefreshRequest(originalConfig)
      ) {
        originalConfig._retry = true;
        if (!refreshPromise) {
          refreshPromise = refreshAccessTokenClient().finally(() => {
            refreshPromise = null;
          });
        }
        const refreshResult = await refreshPromise;
        if (refreshResult.error || !refreshResult.data) {
          const apiError = new CustomError(
            "Unauthorized: Invalid Access Token",
            HttpStatusCode.Unauthorized,
            refreshResult.error ?? details,
          );
          return Promise.reject(apiError);
        }
        const data = refreshResult.data;
        await createSession(
          data.access_token,
          data.refresh_token,
          data.user_roles
            ? JSON.stringify(data.user_roles.map((r) => r.name))
            : "",
          data.anonymous_user,
          data.business_id,
        );
        axiosInstance.defaults.headers.common["Authorization"] =
          `Bearer ${data.access_token}`;
        originalConfig.headers = originalConfig.headers ?? {};
        originalConfig.headers["Authorization"] = `Bearer ${data.access_token}`;
        return axiosInstance(originalConfig);
      }
      let message: string;
      if (error.response) {
        message = getServerErrorMessageSync(status, error, details);
      } else if (error.request) {
        message = "Network Error: Please check your internet connection";
      } else {
        message = error.message || "Request configuration error";
      }
      const apiError = new CustomError(message, status || 500, details);
      if (process.env.NEXT_PUBLIC_NODE_ENV === "development") {
        const logPayload = {
          message: apiError.message,
          status: apiError.status,
          details: apiError.details,
        };
        if (status >= 500 || status === 0) {
          console.error("[API Error]", {
            ...logPayload,
            stack: apiError.stack,
          });
        } else {
          console.warn("[API Error]", logPayload);
        }
      }
      return Promise.reject(apiError);
    },
  );
};
