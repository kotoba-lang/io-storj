(ns storj.protocols
  "The two host seams this library needs: crypto and transport.

  They live in their own namespace so `storj.crypto` (a default implementation)
  and `storj.core` (a consumer) can both depend on them without a cycle, and so
  a host can satisfy them without pulling in either.

  **Return-value contract.** Every method may return either a plain value or a
  thenable. `storj.core` composes them through its own `then`, which is
  identity-application on the JVM and `.then` on JS — so a synchronous
  `javax.crypto` implementation and an asynchronous `crypto.subtle` one drive
  exactly the same code path.")

(defprotocol ICrypto
  "SHA-256 and HMAC-SHA-256. Deliberately tiny: SigV4 needs nothing else, and a
  small surface is one a host can implement in a few lines on any runtime."
  (-sha256-hex [this data]
    "Hex-encoded (lowercase) SHA-256 of `data` — a string or a byte container.")
  (-hmac [this key data]
    "HMAC-SHA-256 of the string `data` under `key` (a string, or the raw byte
    output of a previous `-hmac` — the key-derivation ladder chains them).
    Returns raw bytes.")
  (-hex [this bytes]
    "Lowercase hex encoding of raw bytes, for the final signature."))

(defprotocol IHttp
  "Raw byte transport. The library performs zero network I/O itself; it hands
  you a fully signed request and you put it on the wire."
  (-request [this req]
    "`req` is `{:method :url :headers :body}` with `:headers` a string→string
    map. Returns `{:status :headers :body}` (or a thenable of one). Implementors
    must not follow redirects silently — a redirect invalidates the signature."))
