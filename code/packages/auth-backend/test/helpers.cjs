/**
 * Shared harness for the endpoint-level tests.
 *
 * The middleware is mounted on a REAL `http.Server` bound to loopback and driven with real
 * `fetch`, rather than a hand-built fake req/res pair. A faked ServerResponse is exactly the place
 * a cookie/header bug hides: the tests would assert against our own stub instead of against what
 * Node actually writes on the wire.
 */
const http = require("node:http")

/** Mount a middleware on an ephemeral loopback server. Always `await srv.close()` in a finally. */
async function serve(handler) {
  const server = http.createServer((req, res) => {
    handler(req, res, () => {
      res.statusCode = 404
      res.setHeader("Content-Type", "application/json; charset=utf-8")
      res.end(JSON.stringify({ error: "not_found" }))
    })
  })
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve))
  const { port } = server.address()
  return {
    port,
    base: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  }
}

/** One request against a served middleware. Redirects are never followed — we assert on them. */
async function call(base, path, opts = {}) {
  const res = await fetch(`${base}${path}`, {
    method: opts.method ?? "GET",
    headers: opts.headers ?? {},
    body: opts.body,
    redirect: "manual",
  })
  const text = await res.text()
  let json = null
  try {
    json = JSON.parse(text)
  } catch {
    /* not JSON — fine, callers that care use `text` */
  }
  return {
    status: res.status,
    location: res.headers.get("location"),
    setCookie: res.headers.getSetCookie ? res.headers.getSetCookie() : [],
    headers: res.headers,
    text,
    json,
  }
}

/** Pull one cookie's value out of a Set-Cookie list, or null when it was not set. */
function cookieValue(setCookieList, name) {
  for (const line of setCookieList) {
    const [pair] = line.split(";")
    const eq = pair.indexOf("=")
    if (eq < 0) continue
    if (pair.slice(0, eq).trim() !== name) continue
    const raw = pair.slice(eq + 1).trim()
    if (raw === "") return "" // a cleared cookie
    return decodeURIComponent(raw)
  }
  return null
}

/** Serialize a `{name: value}` map into a Cookie request header. */
function cookieHeader(map) {
  return Object.entries(map)
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join("; ")
}

/** Decode a JWT payload WITHOUT verifying it — tests assert on claims, they don't trust them. */
function jwtPayload(token) {
  const part = token.split(".")[1]
  return JSON.parse(Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"))
}

/** Collect every log line the library emits, so a test can assert on the audit trail. */
function recordingLogger() {
  const lines = []
  const logger = (level, message, meta) => lines.push({ level, message, meta })
  logger.lines = lines
  logger.messages = () => lines.map((l) => l.message)
  return logger
}

module.exports = { serve, call, cookieValue, cookieHeader, jwtPayload, recordingLogger }
