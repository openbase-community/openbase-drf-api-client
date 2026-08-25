import { useEffect } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { AuthenticatorType, Flows } from "../lib/allauth";
import { AuthChangeEvent, useAuthChange, useAuthStatus } from "./hooks";
import { ACCOUNT_PATHS } from "./paths";

export const URLs = Object.freeze({
  LOGIN_URL: ACCOUNT_PATHS.LOGIN,
  LOGIN_REDIRECT_URL: "/dashboard",
  LOGOUT_REDIRECT_URL: "/",
});

// Server-rendered endpoints that live outside the SPA router. Post-login
// redirects to these must be full page loads: a client-side <Navigate> would
// route inside the SPA, drop the request (e.g. a pending OAuth authorize),
// and strand the caller.
const SERVER_PATH_PREFIXES = ["/o/"];

export function isServerPath(path) {
  return SERVER_PATH_PREFIXES.some((prefix) => path.startsWith(prefix));
}

// Every ACCOUNT_PATHS entry lives under this root, so it identifies the auth
// screens without enumerating them.
const ACCOUNT_ROOT = "/account";

export function isAccountPath(pathname) {
  return pathname === ACCOUNT_ROOT || pathname.startsWith(`${ACCOUNT_ROOT}/`);
}

function PostLoginRedirect() {
  const location = useLocation();
  const next = new URLSearchParams(location.search).get("next");
  const path = safeRedirectPath(next);
  const requiresFullPageLoad = isServerPath(path);

  useEffect(() => {
    if (requiresFullPageLoad) {
      window.location.assign(path);
    }
  }, [path, requiresFullPageLoad]);

  if (requiresFullPageLoad) {
    return null;
  }
  return <Navigate to={path} replace />;
}

export function safeRedirectPath(next, fallback = URLs.LOGIN_REDIRECT_URL) {
  if (!next) {
    return fallback;
  }
  if (next.startsWith("/") && !next.startsWith("//")) {
    return next;
  }
  return fallback;
}

const flow2path = {};
flow2path[Flows.LOGIN] = ACCOUNT_PATHS.LOGIN;
flow2path[Flows.LOGIN_BY_CODE] = ACCOUNT_PATHS.LOGIN_CODE_CONFIRM;
flow2path[Flows.SIGNUP] = ACCOUNT_PATHS.SIGNUP;
flow2path[Flows.VERIFY_EMAIL] = ACCOUNT_PATHS.VERIFY_EMAIL;
flow2path[Flows.PASSWORD_RESET_BY_CODE] = ACCOUNT_PATHS.PASSWORD_RESET_CONFIRM;
flow2path[Flows.PROVIDER_SIGNUP] = ACCOUNT_PATHS.PROVIDER_SIGNUP;
flow2path[Flows.REAUTHENTICATE] = ACCOUNT_PATHS.REAUTHENTICATE;
flow2path[Flows.MFA_TRUST] = ACCOUNT_PATHS.MFA_TRUST;
flow2path[`${Flows.MFA_AUTHENTICATE}:${AuthenticatorType.TOTP}`] =
  ACCOUNT_PATHS.AUTHENTICATE_TOTP;
flow2path[`${Flows.MFA_AUTHENTICATE}:${AuthenticatorType.RECOVERY_CODES}`] =
  ACCOUNT_PATHS.AUTHENTICATE_RECOVERY_CODES;
flow2path[`${Flows.MFA_AUTHENTICATE}:${AuthenticatorType.WEBAUTHN}`] =
  ACCOUNT_PATHS.AUTHENTICATE_WEBAUTHN;
flow2path[`${Flows.MFA_REAUTHENTICATE}:${AuthenticatorType.TOTP}`] =
  ACCOUNT_PATHS.REAUTHENTICATE_TOTP;
flow2path[`${Flows.MFA_REAUTHENTICATE}:${AuthenticatorType.RECOVERY_CODES}`] =
  ACCOUNT_PATHS.REAUTHENTICATE_RECOVERY_CODES;
flow2path[`${Flows.MFA_REAUTHENTICATE}:${AuthenticatorType.WEBAUTHN}`] =
  ACCOUNT_PATHS.REAUTHENTICATE_WEBAUTHN;
flow2path[Flows.MFA_WEBAUTHN_SIGNUP] = ACCOUNT_PATHS.SIGNUP_PASSKEY_CREATE;

export function pathForFlow(flow, typ) {
  let key = flow.id;
  if (typeof flow.types !== "undefined") {
    typ = typ ?? flow.types[0];
    key = `${key}:${typ}`;
  }
  const path = flow2path[key] ?? flow2path[flow.id];
  if (!path) {
    throw new Error(`Unknown path for flow: ${flow.id}`);
  }
  return path;
}

export function pathForPendingFlow(auth) {
  const flow = auth.data.flows.find((flow) => flow.is_pending);
  if (flow) {
    return pathForFlow(flow);
  }
  return null;
}

// Multi-step sign-in (login-by-code, MFA, email verification, passkey signup)
// hops between flow steps before the session exists. Each hop must carry the
// pending `?next=` forward: the destination is only read once, at the end of the
// flow, so dropping it here strands the user on LOGIN_REDIRECT_URL instead of
// wherever they were headed. It is re-validated on every hop rather than only at
// the end, so a hostile value never survives a transition.
function navigateToPendingFlow(auth, location) {
  const path = pathForPendingFlow(auth);
  if (!path) {
    return null;
  }
  return <Navigate to={withNext(path, location)} replace />;
}

function withNext(path, location) {
  const next = new URLSearchParams(location.search).get("next");
  if (!next) {
    return path;
  }
  return `${path}?next=${encodeURIComponent(safeRedirectPath(next))}`;
}

export function AuthenticatedRoute({ children }) {
  const location = useLocation();
  const [, status] = useAuthStatus();
  const next = `next=${encodeURIComponent(
    location.pathname + location.search
  )}`;
  if (status.isAuthenticated) {
    return children;
  } else {
    return <Navigate to={`${URLs.LOGIN_URL}?${next}`} />;
  }
}

export function AnonymousRoute({ children }) {
  const [, status] = useAuthStatus();
  if (!status.isAuthenticated) {
    return children;
  } else {
    return <PostLoginRedirect />;
  }
}

export function AuthChangeRedirector({ children }) {
  const [auth, event] = useAuthChange();
  const location = useLocation();
  switch (event) {
    case AuthChangeEvent.LOGGED_OUT:
      return <Navigate to={URLs.LOGOUT_REDIRECT_URL} />;
    case AuthChangeEvent.LOGGED_IN:
      // Every auth screen is wrapped in AnonymousRoute, which redirects on this
      // same transition and renders a beat earlier. By the time this case runs
      // the user is usually already at their destination -- a location with no
      // `next` to read, where PostLoginRedirect would fall back to
      // LOGIN_REDIRECT_URL and undo the redirect that just happened. Only take
      // over while still on an auth screen, which is the case AnonymousRoute
      // cannot finish: a server-path destination leaves the SPA location
      // untouched because it navigates via window.location.
      return isAccountPath(location.pathname) ? <PostLoginRedirect /> : children;
    case AuthChangeEvent.REAUTHENTICATED: {
      const next = new URLSearchParams(location.search).get("next");
      return <Navigate to={safeRedirectPath(next, "/")} />;
    }
    case AuthChangeEvent.REAUTHENTICATION_REQUIRED: {
      const next = `next=${encodeURIComponent(
        location.pathname + location.search
      )}`;
      // Prefer the pending flow over flows[0]: allauth lists every reauth
      // method it will accept, and the first is not necessarily the one to
      // run. Picking wrong can land on a step the device cannot complete
      // (e.g. WebAuthn inside a webview).
      const path =
        pathForPendingFlow(auth) ?? pathForFlow(auth.data.flows[0]);
      return <Navigate to={`${path}?${next}`} state={{ reauth: auth }} />;
    }
    case AuthChangeEvent.FLOW_UPDATED:
      const pendingFlow = navigateToPendingFlow(auth, location);
      if (!pendingFlow) {
        throw new Error(
          `FLOW_UPDATED auth event had no pending flow to navigate to; flows: ${JSON.stringify(
            auth?.data?.flows ?? null
          )}`
        );
      }
      return pendingFlow;
    default:
      break;
  }
  // ...stay where we are
  return children;
}
