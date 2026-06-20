import { jsx as _jsx } from "react/jsx-runtime";
import { createContext, useContext, useEffect, useMemo, useRef, useState, useSyncExternalStore, } from "react";
import { DevAuthCore, RealAuthCore } from "./core.js";
const AuthContext = createContext(null);
export function useAuthContext() {
    const ctx = useContext(AuthContext);
    if (!ctx) {
        throw new Error("OpenAuthFederated: hooks and components must be used inside <AuthProvider>.");
    }
    return ctx;
}
export function AuthProvider(props) {
    const coreRef = useRef(null);
    if (!coreRef.current) {
        const domains = props.allowedDomains && props.allowedDomains.length > 0
            ? props.allowedDomains
            : ["act3ai.com", "whitehatengineering.com"];
        coreRef.current = props.devMode
            ? new DevAuthCore(domains, props.devSharedSecret ?? "dev-shared-secret", props.frontendApi ?? "https://auth.dev.local")
            : new RealAuthCore(props.frontendApi ?? "", props.publishableKey ?? "", domains);
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
    const snapshot = useSyncExternalStore((cb) => core.subscribe(cb), () => core.getSnapshot(), () => core.getSnapshot());
    const value = useMemo(() => ({
        core,
        snapshot,
        isLoaded,
        connections: core.connections(),
        config: {
            signInUrl: props.signInUrl ?? "/sign-in",
            signUpUrl: props.signUpUrl ?? "/sign-up",
            afterSignOutUrl: props.afterSignOutUrl ?? "/sign-in",
            appearance: props.appearance,
        },
    }), [core, snapshot, isLoaded, props.signInUrl, props.signUpUrl, props.afterSignOutUrl, props.appearance]);
    return _jsx(AuthContext.Provider, { value: value, children: props.children });
}
//# sourceMappingURL=context.js.map