"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import * as jose from "jose";
import { HttpStatusCode } from "axios";
import axiosInstance from "./api";

const MAX_ACCESS_TOKEN_AGE = process.env.NEXT_PUBLIC_MAX_ACCESS_TOKEN_AGE!;
const MAX_REFRESH_TOKEN_AGE = process.env.NEXT_PUBLIC_MAX_REFRESH_TOKEN_AGE!;

const COOKIE_ACCESS_TOKEN_KEY = "access_token";
const COOKIE_BUSINESS_ID = "business_id";
const COOKIE_REFRESH_TOKEN_KEY = "refresh_token";
const COOKIE_IS_ANONYMOUS_USER_KEY = "anonymous_user";
const COOKIE_DEVICE_ID_KEY = "device_id";
const COOKIE_USER_ROLES = "roles";

const PATRON = "patron";
const ADMIN = "admin";
const BUSINESS_OWNER = "business_owner";

const getBaseDomain = (subdomain: string) => {
  if (subdomain === "") {
    return undefined;
  }
  const match = subdomain.match(/([a-zA-Z0-9-]+\.[a-zA-Z]+)$/);
  return match ? `.${match[0]}` : undefined;
};

export async function createSession(
  accessToken: string,
  refreshToken: string,
  roles: string,
  anonymousUser: "yes" | "no",
  businessId?: string,
): Promise<void> {
  const cookieStore = await cookies();
  const domain =
    process.env.NEXT_PUBLIC_NODE_ENV === "production"
      ? getBaseDomain(process.env.NEXT_PUBLIC_APP_URL || "")
      : undefined;
  const COOKIE_SETTINGS = {
    secure: process.env.NEXT_PUBLIC_NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/",
    httpOnly: true,
    maxAge: Number(MAX_ACCESS_TOKEN_AGE),
    domain: domain || undefined,
  };
  const REFRESH_COOKIE_SETTINGS = {
    secure: process.env.NEXT_PUBLIC_NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/",
    httpOnly: true,
    maxAge: Number(MAX_REFRESH_TOKEN_AGE),
    domain: domain || undefined,
  };
  try {
    if (accessToken && typeof accessToken === "string") {
      cookieStore.set(COOKIE_ACCESS_TOKEN_KEY, accessToken, COOKIE_SETTINGS);
    } else if (accessToken) {
      console.log("Invalid accessToken provided");
    }
    if (refreshToken && typeof refreshToken === "string") {
      cookieStore.set(
        COOKIE_REFRESH_TOKEN_KEY,
        refreshToken,
        REFRESH_COOKIE_SETTINGS,
      );
    } else if (refreshToken) {
      console.log("Invalid refreshToken provided");
    }
    if (roles && typeof roles === "string") {
      cookieStore.set(COOKIE_USER_ROLES, roles, COOKIE_SETTINGS);
    } else if (roles) {
      console.log("Invalid roles provided");
    }
    if (anonymousUser && ["yes", "no"].includes(anonymousUser)) {
      cookieStore.set(
        COOKIE_IS_ANONYMOUS_USER_KEY,
        anonymousUser,
        COOKIE_SETTINGS,
      );
    } else if (anonymousUser) {
      console.log("Invalid anonymousUser value provided");
    }
    if (businessId && typeof businessId === "string") {
      cookieStore.set(COOKIE_BUSINESS_ID, businessId, COOKIE_SETTINGS);
    } else if (businessId) {
      console.log("Invalid businessId provided");
    }
  } catch (error) {
    console.error("Error setting cookies:", error);
  }
}

export async function verifySession() {
  const cookieStore = await cookies();
  const accessToken = cookieStore.get(COOKIE_ACCESS_TOKEN_KEY)?.value;
  const businessId = cookieStore.get(COOKIE_BUSINESS_ID)?.value;
  const refreshToken = cookieStore.get(COOKIE_REFRESH_TOKEN_KEY)?.value;
  const ip = cookieStore.get("x-client-ip")?.value || "";
  const isAnonymousUser =
    cookieStore.get(COOKIE_IS_ANONYMOUS_USER_KEY)?.value === "yes";
  const deviceId = cookieStore.get(COOKIE_DEVICE_ID_KEY)?.value;
  const isLoggedIn = !!accessToken && !isAnonymousUser;
  if (accessToken) {
    try {
      await jose.jwtVerify(
        accessToken,
        new TextEncoder().encode(process.env.JWT_KEY),
      );
    } catch (err) {
      if ((err as { code: string }).code === "ERR_JWT_EXPIRED") {
        try {
          if (!refreshToken || !deviceId) {
            redirect(`/logout?token=expired`);
          }
          const { status, data: result } = await axiosInstance.post(
            `/v2/auth/refresh`,
            {
              refresh_token: refreshToken,
            },
            {
              headers: {
                "device-id": deviceId,
              },
            },
          );
          if (
            status !== HttpStatusCode.Ok ||
            result.statusCode !== HttpStatusCode.Ok ||
            !result.data ||
            !result.data.access_token ||
            !result.data.refresh_token ||
            !result.data.user?.user_roles
          ) {
            redirect(`/logout?token=expired`);
          }
          await createSession(
            result.data.access_token,
            result.data.refresh_token,
            result.data.user?.user_roles
              ? JSON.stringify(
                  result.data.user?.user_roles?.map(
                    (r: { id: string; name: string }) => r.name,
                  ),
                )
              : "",
            "no",
            result.data.user?.user_business_access?.[0]?.business_id,
          );
          const isAdmin =
            result.data.user?.user_roles?.filter(
              (item: { id: string; name: string }) => item.name === ADMIN,
            ).length === 1;
          const isPatron =
            result.data.user?.user_roles?.filter(
              (item: { id: string; name: string }) => item.name === PATRON,
            ).length === 1;
          const isBusinessOwner =
            result.data.user?.user_roles?.filter(
              (item: { id: string; name: string }) =>
                item.name === BUSINESS_OWNER,
            ).length === 1;
          console.log({
            isLoggedIn: true,
            isAdmin: isAdmin,
            isPatron: isPatron,
            isBusinessOwner: isBusinessOwner,
            accessToken: result.data.access_token,
            deviceId,
            businessId:
              result.data.user?.user_business_access?.[0]?.business_id,
          });
          return {
            isLoggedIn: true,
            isAdmin: isAdmin,
            isPatron: isPatron,
            isBusinessOwner: isBusinessOwner,
            accessToken: result.data.access_token,
            deviceId,
            businessId:
              result.data.user?.user_business_access?.[0]?.business_id,
          };
        } catch (error) {
          console.error("Error refreshing access token:", error);
          redirect(`/logout?token=expired`);
        }
      }
    }
  } else {
    try {
      if (!refreshToken || !deviceId) {
        redirect(`/logout?token=expired`);
      }
      const { status, data: result } = await axiosInstance.post(
        `/v2/auth/refresh`,
        {
          refresh_token: refreshToken,
        },
        {
          headers: {
            "device-id": deviceId,
          },
        },
      );
      if (
        status !== HttpStatusCode.Ok ||
        result.statusCode !== HttpStatusCode.Ok ||
        !result.data ||
        !result.data.access_token ||
        !result.data.refresh_token ||
        !result.data.user?.user_roles
      ) {
        redirect(`/logout?token=expired`);
      }
      await createSession(
        result.data.access_token,
        result.data.refresh_token,
        result.data.user?.user_roles
          ? JSON.stringify(
              result.data.user?.user_roles?.map(
                (r: { id: string; name: string }) => r.name,
              ),
            )
          : "",
        "no",
        result.data.user?.user_business_access?.[0]?.business_id,
      );
      const isAdmin =
        result.data.user?.user_roles?.filter(
          (item: { id: string; name: string }) => item.name === ADMIN,
        ).length === 1;
      const isPatron =
        result.data.user?.user_roles?.filter(
          (item: { id: string; name: string }) => item.name === PATRON,
        ).length === 1;
      const isBusinessOwner =
        result.data.user?.user_roles?.filter(
          (item: { id: string; name: string }) => item.name === BUSINESS_OWNER,
        ).length === 1;
      console.log({
        isLoggedIn: true,
        isAdmin: isAdmin,
        isPatron: isPatron,
        isBusinessOwner: isBusinessOwner,
        accessToken: result.data.access_token,
        deviceId,
        businessId: result.data.user?.user_business_access?.[0]?.business_id,
      });
      return {
        isLoggedIn: true,
        isAdmin: isAdmin,
        isPatron: isPatron,
        isBusinessOwner: isBusinessOwner,
        accessToken: result.data.access_token,
        deviceId,
        businessId: result.data.user?.user_business_access?.[0]?.business_id,
      };
    } catch (error) {
      console.error("Error refreshing access token:", error);
    }
  }
  let userRoles: string | string[] | undefined =
    cookieStore.get(COOKIE_USER_ROLES)?.value;
  let isAdmin = false;
  let isPatron = false;
  let isBusinessOwner = false;
  if (userRoles && userRoles !== "undefined") {
    userRoles = JSON.parse(userRoles) as string[];
    isAdmin = userRoles?.filter((item) => item === ADMIN).length === 1;
    isPatron = userRoles?.filter((item) => item === PATRON).length === 1;
    isBusinessOwner =
      userRoles?.filter((item) => item === BUSINESS_OWNER).length === 1;
  }
  return {
    isLoggedIn: isLoggedIn,
    isAdmin: isAdmin,
    isPatron: isPatron,
    isBusinessOwner: isBusinessOwner,
    accessToken,
    deviceId,
    businessId,
    ip,
  };
}
