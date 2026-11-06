import { jsx as _jsx } from "react/jsx-runtime";
import { createContext, useContext, useEffect, useMemo, useRef, useState, useSyncExternalStore, } from "react";
import { RealAuthCore } from "./core.js";
const AuthContext = createContext(null);
export function useAuthContext() {
    const ctx = useContext(AuthContext);
    if (!ctx) {
        throw new Error("OpenAuthFederated: hooks and components must be used inside <FederatedProvider>.");
    }
    return ctx;
}
/**
 * Root provider `<FederatedProvider>`: wrap the app, pass `publishableKey` / `frontendApi`, and the
 * hooks/components become available. `<AuthProvider>` is kept as an alias.
 */
export function FederatedProvider(props) {
    const coreRef = useRef(null);
    if (!coreRef.current) {
        // Default to the real federated client. OpenAuthFederated ships no dev mock and NO default
        // domain list: the buttons come from the app (connections / allowedDomains), the server's
        // /environment, or one generic Google button. An app that wants a localhost-only dev core builds
        // its own and injects it via `core` (gated on its own side).
        coreRef.current =
            props.core ??
                new RealAuthCore(props.frontendApi ?? "", props.publishableKey ?? "", props.allowedDomains, props.connections);
    }
    const core = coreRef.current;
    const [isLoaded, setIsLoaded] = useState(false);
    useEffect(() => {
        let active = true;
        core.load().finally(() => {
            if (active)
                setIsLoaded(true);
        });
        return () => {
            active = false;
        };
    }, [core]);
    // ONE subscription, not two. Subscribing separately for `snapshot` and `loadState` registered two
    // listeners per provider and walked the listener set twice on every emit, for two values that
    // always change together and always come from the same store.
    const subscribe = useMemo(() => (cb) => core.subscribe(cb), [core]);
    const snapshot = useSyncExternalStore(subscribe, () => core.getSnapshot(), () => core.getSnapshot());
    const loadState = useSyncExternalStore(subscribe, () => core.loadState(), () => core.loadState());
    // `connections` is a stable, frozen reference that changes at most once (when the server's
    // /environment supplies the buttons), so reading it through the store costs nothing per render.
    const connections = useSyncExternalStore(subscribe, () => core.connections(), () => core.connections());
    const value = useMemo(() => ({
        core,
        snapshot,
        isLoaded,
        loadState,
        connections,
        config: {
            signInUrl: props.signInUrl ?? "/sign-in",
            signUpUrl: props.signUpUrl ?? "/sign-up",
            afterSignOutUrl: props.afterSignOutUrl ?? "/sign-in",
            appearance: props.appearance,
        },
    }), [
        core,
        snapshot,
        isLoaded,
        loadState,
        connections,
        props.signInUrl,
        props.signUpUrl,
        props.afterSignOutUrl,
        props.appearance,
    ]);
    return _jsx(AuthContext.Provider, { value: value, children: props.children });
}
/**
 * @deprecated Use {@link FederatedProvider}. Alias retained so existing `<AuthProvider>` usage keeps
 * working unchanged.
 */
export const AuthProvider = FederatedProvider;
//# sourceMappingURL=context.js.map