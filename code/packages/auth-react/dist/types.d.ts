/** Theming overrides for the drop-in components (`@auth/ui` is folded in here). */
export interface Appearance {
    variables?: {
        colorPrimary?: string;
    } & Record<string, string>;
}
/** The signed-in user as exposed to the app. */
export interface SdkUser {
    id: string;
    firstName?: string;
    lastName?: string;
    primaryEmailAddress?: string;
    imageUrl?: string;
    publicMetadata?: Record<string, unknown>;
    roles: string[];
    permissions: string[];
    /** Upstream hosted-domain (Google Workspace `hd`). */
    hd?: string;
}
/** An organization/tenant the signed-in user belongs to. */
export interface SdkOrganization {
    id: string;
    name: string;
    slug?: string;
    membersCount?: number;
    publicMetadata?: Record<string, unknown>;
}
/** The current user's membership in an organization — carries their role + permissions. */
export interface SdkMembership {
    id: string;
    organization: SdkOrganization;
    role: string;
    permissions: string[];
}
/** Immutable snapshot of auth state, surfaced through `useSyncExternalStore`. */
export interface SessionSnapshot {
    isSignedIn: boolean;
    userId: string | null;
    sessionId: string | null;
    /** The active organization/tenant id (per browser tab). */
    orgId: string | null;
    user: SdkUser | null;
    /** Every organization the user belongs to (for the switcher / org list). */
    memberships: SdkMembership[];
    /** Epoch-seconds the active session was last verified — drives step-up reverification. */
    lastVerifiedAt: number | null;
}
/** A federated "global login" — one company Workspace domain/SSO connection. */
export interface Connection {
    id: string;
    domain: string;
    label: string;
}
export interface AuthenticateWithRedirectParams {
    strategy?: string;
    connectionId?: string;
    redirectUrl: string;
    redirectUrlComplete: string;
}
/**
 * An attempt that the platform refused — e.g. a valid upstream identity whose verified domain
 * is not on the allowlist (`identity_domain_not_allowed`). No user is created and no session is
 * established; the SDK surfaces this so the app can show a clear "restricted to company
 * accounts" message. Mirrors the documented callback rejection
 * (`docs/apis/frontend/sign-up.mdx#domain-enforcement`).
 */
export interface AuthRejection {
    code: string;
    message: string;
    /** The verified domain the upstream identity presented, when known. */
    presentedDomain?: string;
}
/**
 * The outcome of completing a redirect handshake on the callback route. Exactly one of
 * `redirectTo` (success → forward the user on) or `error` (rejection → return to sign-in with
 * a message) is populated.
 */
export interface RedirectCallbackResult {
    redirectTo?: string;
    error?: AuthRejection;
}
export interface PermissionCheck {
    role?: string;
    permission?: string;
}
/** The SDK lifecycle state — drives `<AuthLoading>` / `<AuthLoaded>` / `<AuthFailed>`. */
export type LoadState = "loading" | "loaded" | "degraded" | "failed";
/**
 * The framework-agnostic engine behind the provider. Two implementations exist: a real
 * Frontend-API client and a local dev mock (see core.ts).
 */
export interface AuthCore {
    load(): Promise<void>;
    loadState(): LoadState;
    getSnapshot(): SessionSnapshot;
    subscribe(listener: () => void): () => void;
    connections(): Connection[];
    getToken(opts?: {
        template?: string;
    }): Promise<string | null>;
    authenticateWithRedirect(params: AuthenticateWithRedirectParams): Promise<void>;
    completeRedirectCallback(): Promise<RedirectCallbackResult>;
    signOut(opts?: {
        redirectUrl?: string;
    }): Promise<void>;
    has(check?: PermissionCheck): boolean;
    /** Switch the active organization for this tab; resolves once the snapshot reflects it. */
    setActiveOrg(orgId: string | null): Promise<void>;
    /** Re-establish a freshly-verified session (step-up MFA) for sensitive actions. */
    reverify(): Promise<void>;
    /** Whether the active session was verified within `maxAgeSeconds`. */
    isRecentlyVerified(maxAgeSeconds: number): boolean;
}
export declare const EMPTY_SNAPSHOT: SessionSnapshot;
/**
 * Wildcard-aware permission check — exact grant, feature wildcard (`film:*`), action
 * wildcard (`*:read`), or super-wildcard (`*:*`). Also handles the spec's structured
 * three-part permissions (`org:invoices:create`, `org:sys_memberships:manage`) by treating
 * everything before the final `:` as the feature. Mirrors the backend SDK helper.
 */
export declare function hasPermission(granted: string[], permission: string): boolean;
/** Role match — accepts a bare role (`admin`) or its `org:`-prefixed form interchangeably. */
export declare function hasRole(roles: string[], role: string): boolean;
export declare function domainSlug(domain: string): string;
