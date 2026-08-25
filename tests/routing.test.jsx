import React, { useState } from "react";
import { act, create } from "react-test-renderer";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { AuthContext } from "../src/auth/AuthContext";
import { AnonymousRoute, AuthChangeRedirector } from "../src/auth/routing";

const anonymousAuth = {
  status: 401,
  meta: { is_authenticated: false },
  data: { flows: [] },
};

const authenticatedAuth = {
  status: 200,
  meta: { is_authenticated: true },
  data: { flows: [], methods: [], user: { id: 1 } },
};

// Intermediate states: signed-in-but-not-finished. allauth reports these as
// anonymous with a pending flow, and the SPA hops to that flow's screen before
// the session exists.
const pendingLoginCodeAuth = {
  status: 401,
  meta: { is_authenticated: false },
  data: { flows: [{ id: "login_by_code", is_pending: true }] },
};

const pendingMfaAuth = {
  status: 401,
  meta: { is_authenticated: false },
  data: {
    flows: [{ id: "mfa_authenticate", is_pending: true, types: ["totp"] }],
  },
};

let authenticate;
let setAuthState;
let currentLocation;

function LocationCapture() {
  const location = useLocation();
  currentLocation = location.pathname + location.search;
  return null;
}

function AuthHarness({ initialAuth = anonymousAuth }) {
  const [auth, setAuth] = useState(initialAuth);
  authenticate = () => setAuth(authenticatedAuth);
  setAuthState = (next) => setAuth(next);

  return (
    <AuthContext.Provider value={{ auth, config: { status: 200 } }}>
      <AuthChangeRedirector>
        <LocationCapture />
        <Routes>
          <Route
            path="/account/login"
            element={
              <AnonymousRoute>
                <div>Login</div>
              </AnonymousRoute>
            }
          />
          <Route
            path="/account/login/code/confirm"
            element={
              <AnonymousRoute>
                <div>Confirm login code</div>
              </AnonymousRoute>
            }
          />
          <Route
            path="/account/authenticate/totp"
            element={
              <AnonymousRoute>
                <div>TOTP</div>
              </AnonymousRoute>
            }
          />
          <Route path="/dashboard" element={<div>Dashboard</div>} />
          <Route path="/dashboard/settings" element={<div>Settings</div>} />
          <Route path="/settings/billing" element={<div>Billing</div>} />
        </Routes>
      </AuthChangeRedirector>
    </AuthContext.Provider>
  );
}

async function renderAt(path, initialAuth) {
  let renderer;
  await act(async () => {
    renderer = create(
      <MemoryRouter
        initialEntries={[path]}
        future={{ v7_relativeSplatPath: true, v7_startTransition: true }}
      >
        <AuthHarness initialAuth={initialAuth} />
      </MemoryRouter>,
    );
  });
  return renderer;
}

describe("post-login redirects", () => {
  beforeEach(() => {
    authenticate = undefined;
    currentLocation = undefined;
    vi.stubGlobal("window", {
      location: { assign: vi.fn() },
      sessionStorage: window.sessionStorage,
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("preserves a server destination through the login state transition", async () => {
    const destination =
      "/o/authorize/?response_type=code&client_id=openbase-coder-cli" +
      "&redirect_uri=http%3A%2F%2F127.0.0.1%3A52807%2Foauth%2Fcallback" +
      "&code_challenge=WaDc6KvXdxh0eMqo8cWhWQK7Qu7reXxPfYN4byKzAkA" +
      "&code_challenge_method=S256&state=f9bd0cb6011259d254e84ee735c5b706";
    const renderer = await renderAt(
      `/account/login?next=${encodeURIComponent(destination)}`,
    );

    await act(async () => {
      authenticate();
    });

    expect(window.location.assign).toHaveBeenCalledWith(destination);
    expect(currentLocation).not.toBe("/dashboard");
    renderer.unmount();
  });

  it("honors a server destination for an existing authenticated session", async () => {
    const destination = "/o/authorize/?client_id=openbase-coder-cli";
    const renderer = await renderAt(
      `/account/login?next=${encodeURIComponent(destination)}`,
      authenticatedAuth,
    );

    expect(window.location.assign).toHaveBeenCalledWith(destination);
    expect(currentLocation).not.toBe("/dashboard");
    renderer.unmount();
  });

  it("uses client-side navigation for an internal destination", async () => {
    const renderer = await renderAt(
      "/account/login?next=%2Fdashboard%2Fsettings",
      authenticatedAuth,
    );

    expect(currentLocation).toBe("/dashboard/settings");
    expect(window.location.assign).not.toHaveBeenCalled();
    renderer.unmount();
  });

  // AnonymousRoute and the LOGGED_IN case both redirect on this transition. The
  // second must not re-resolve against the already-redirected location, where
  // there is no `next` left to read.
  it("preserves an internal destination through the login state transition", async () => {
    const renderer = await renderAt("/account/login?next=%2Fsettings%2Fbilling");

    await act(async () => {
      authenticate();
    });

    expect(currentLocation).toBe("/settings/billing");
    expect(window.location.assign).not.toHaveBeenCalled();
    renderer.unmount();
  });
});

describe("post-login redirects through a multi-step flow", () => {
  beforeEach(() => {
    authenticate = undefined;
    setAuthState = undefined;
    currentLocation = undefined;
    vi.stubGlobal("window", {
      location: { assign: vi.fn() },
      sessionStorage: window.sessionStorage,
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("keeps the destination across an emailed login code", async () => {
    const renderer = await renderAt(
      "/account/login?next=%2Fsettings%2Fbilling",
    );

    await act(async () => {
      setAuthState(pendingLoginCodeAuth);
    });
    expect(currentLocation).toBe(
      "/account/login/code/confirm?next=%2Fsettings%2Fbilling",
    );

    await act(async () => {
      authenticate();
    });

    expect(currentLocation).toBe("/settings/billing");
    renderer.unmount();
  });

  it("keeps the destination across an MFA challenge", async () => {
    const renderer = await renderAt(
      "/account/login?next=%2Fsettings%2Fbilling",
    );

    await act(async () => {
      setAuthState(pendingMfaAuth);
    });
    expect(currentLocation).toBe(
      "/account/authenticate/totp?next=%2Fsettings%2Fbilling",
    );

    await act(async () => {
      authenticate();
    });

    expect(currentLocation).toBe("/settings/billing");
    renderer.unmount();
  });

  it("falls back to the default destination when no next was set", async () => {
    const renderer = await renderAt("/account/login");

    await act(async () => {
      setAuthState(pendingLoginCodeAuth);
    });
    expect(currentLocation).toBe("/account/login/code/confirm");

    await act(async () => {
      authenticate();
    });

    expect(currentLocation).toBe("/dashboard");
    renderer.unmount();
  });

  it("neutralises an off-site destination as it crosses a flow step", async () => {
    const renderer = await renderAt(
      `/account/login?next=${encodeURIComponent("//evil.example")}`,
    );

    await act(async () => {
      setAuthState(pendingLoginCodeAuth);
    });
    expect(currentLocation).toBe(
      "/account/login/code/confirm?next=%2Fdashboard",
    );

    await act(async () => {
      authenticate();
    });

    expect(currentLocation).toBe("/dashboard");
    expect(window.location.assign).not.toHaveBeenCalled();
    renderer.unmount();
  });
});
