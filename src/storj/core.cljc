(ns storj.core
  "Signed S3 operations against a Storj Gateway-MT endpoint.

  This namespace owns request *composition* — it never opens a socket and never
  computes a digest. You supply an `ICrypto` and an `IHttp` (`storj.crypto` has
  a default for the former); it supplies correctly signed requests.

  **One code path, two runtimes.** JVM crypto is synchronous, `crypto.subtle` is
  Promise-based. Rather than fork the signing logic, everything is composed
  through `then`, which is plain application on the JVM and `.then` on JS. The
  consequence for callers: on the JVM these functions return values, on
  ClojureScript they return Promises of the same values — the shape is
  identical, only the wrapper differs. That mirrors `kotoba.lang.ipfs`."
  (:require [clojure.string :as str]
            [storj.gateway :as gw]
            [storj.protocols :as p]
            [storj.sigv4 :as v4]))

(defn- then
  "Apply `f` to `v`, threading through a Promise on JS. The single point where
  this library's sync/async duality lives."
  [v f]
  #?(:clj  (f v)
     :cljs (.then (js/Promise.resolve v) f)))

(defn client
  "Build a client from a validated gateway config plus host implementations.

      (client {:bucket \"b\" :access-key \"...\" :secret-key \"...\"}
              {:crypto (storj.crypto/crypto) :http my-http})

  Validation happens here, once, so every later request is signed against
  known-good config."
  [config {:keys [crypto http]}]
  {:pre [(satisfies? p/ICrypto crypto)]}
  {:config (gw/validate config) :crypto crypto :http http})

;; ── signing ──────────────────────────────────────────────────────────────────

(defn- base-headers [{:keys [host]} payload-hash long-date extra]
  (merge {"host"                 host
          "x-amz-content-sha256" payload-hash
          "x-amz-date"           long-date}
         extra))

(defn- derive-signature
  "Fold the HMAC ladder and sign `sts`. → hex signature (or a thenable of one)."
  [crypto secret short-date region sts]
  (let [{:keys [secret steps]} (v4/signing-key-chain secret short-date region)]
    (then (reduce (fn [k step] (then k #(p/-hmac crypto % step))) secret steps)
          (fn [signing-key]
            (then (p/-hmac crypto signing-key sts)
                  #(p/-hex crypto %))))))

(defn sign
  "Sign one request against `config`. → `{:method :url :headers :body}`.

  `req` is `{:method :key :query :headers :body :payload-hash :now}`:
  `:now` is an ISO-8601 instant *you* supply (the library reads no clock, which
  is what makes signing reproducible and testable); `:payload-hash` defaults to
  the SHA-256 of `:body`, or the empty-string hash when there is no body."
  [{:keys [config crypto]} {:keys [method key query headers body payload-hash now]}]
  (let [{:keys [bucket region origin access-key secret-key]} config
        {:keys [long short]} (v4/amz-dates now)
        path (v4/object-path bucket key)
        qs   (v4/canonical-query query)]
    (then (or payload-hash
              (if (some? body) (p/-sha256-hex crypto body) v4/empty-payload-sha256))
          (fn [payload-hash]
            (let [headers (base-headers config payload-hash long headers)
                  {:keys [canonical-request signed-headers]}
                  (v4/canonical-request {:method       method
                                         :path         path
                                         :query        qs
                                         :headers      headers
                                         :payload-hash payload-hash})
                  scope (v4/credential-scope short region)]
              (then (p/-sha256-hex crypto canonical-request)
                    (fn [cr-hash]
                      (then (derive-signature crypto secret-key short region
                                              (v4/string-to-sign long scope cr-hash))
                            (fn [signature]
                              {:method  (str/upper-case (name method))
                               :url     (str origin path (when (seq qs) (str "?" qs)))
                               :headers (assoc headers "authorization"
                                               (v4/authorization-header
                                                access-key scope signed-headers signature))
                               :body    body})))))))))

(defn presign
  "Presigned URL for `key` — a bare `https://…?X-Amz-…` string anyone can fetch
  until it expires, with no credentials on the wire.

  `:expires-seconds` defaults to 3600 and is capped by S3 at 604800 (7 days).
  Only the `host` header is signed, so the URL works from a browser."
  [{:keys [config crypto]} {:keys [method key query now expires-seconds]
                            :or   {method :get expires-seconds 3600}}]
  (let [{:keys [bucket region origin host access-key secret-key]} config
        {:keys [long short]} (v4/amz-dates now)
        scope  (v4/credential-scope short region)
        path   (v4/object-path bucket key)
        params (merge query
                      (v4/presign-params {:key-id          access-key
                                          :scope           scope
                                          :long-date       long
                                          :expires-seconds expires-seconds
                                          :signed-headers  "host"}))
        qs     (v4/canonical-query params)
        {:keys [canonical-request]}
        (v4/canonical-request {:method       method
                               :path         path
                               :query        qs
                               :headers      {"host" host}
                               :payload-hash v4/unsigned-payload})]
    (then (p/-sha256-hex crypto canonical-request)
          (fn [cr-hash]
            (then (derive-signature crypto secret-key short region
                                    (v4/string-to-sign long scope cr-hash))
                  (fn [signature]
                    (str origin path "?" qs "&X-Amz-Signature=" signature)))))))

;; ── operations ───────────────────────────────────────────────────────────────

(defn- send! [{:keys [http] :as client} req]
  (then (sign client req) #(p/-request http %)))

(defn- expect
  "Return the response when its status is in `ok`, otherwise throw with enough
  context to debug — the status and the operation, never the credentials."
  [resp ok op]
  (if (contains? ok (:status resp))
    resp
    (throw (ex-info (str "Storj " op " failed: HTTP " (:status resp))
                    {:type ::request-failed :status (:status resp) :op op}))))

(defn get-object
  "GET an object. → the response, or `nil` on 404.

  `:range` (e.g. `\"bytes=0-1023\"`) is signed as a header, so a partial read is
  as cheap as a full one."
  [client {:keys [key now range]}]
  (then (send! client {:method :get :key key :now now
                       :headers (when range {"range" range})})
        (fn [resp]
          (when-not (= 404 (:status resp))
            (expect resp #{200 206} (str "GET " key))))))

(defn head-object
  "HEAD an object → `{:status :headers}`, or `nil` on 404. Cheapest existence
  and size check."
  [client {:keys [key now]}]
  (then (send! client {:method :head :key key :now now})
        (fn [resp]
          (when-not (= 404 (:status resp))
            (expect resp #{200} (str "HEAD " key))))))

(defn put-object
  "PUT an object. `body` is bytes or a string; `:content-type` is signed."
  [client {:keys [key body now content-type]}]
  (then (send! client {:method :put :key key :body body :now now
                       :headers (when content-type {"content-type" content-type})})
        #(expect % #{200} (str "PUT " key))))

(defn delete-object
  "DELETE an object. S3 returns 204 whether or not the key existed, so this is
  idempotent."
  [client {:keys [key now]}]
  (then (send! client {:method :delete :key key :now now})
        #(expect % #{204 200} (str "DELETE " key))))

(defn list-objects
  "ListObjectsV2 over the bucket. → the raw response; run `:body` through
  `parse-list-result` for the keys.

  `:prefix`, `:max-keys`, and `:continuation-token` map to their S3 parameters;
  pass the previous page's `:next-continuation-token` to paginate."
  [client {:keys [prefix max-keys continuation-token now delimiter]}]
  (then (send! client
               {:method :get :key nil :now now
                :query (cond-> {"list-type" "2"}
                         prefix             (assoc "prefix" prefix)
                         delimiter          (assoc "delimiter" delimiter)
                         max-keys           (assoc "max-keys" (str max-keys))
                         continuation-token (assoc "continuation-token" continuation-token))})
        #(expect % #{200} "LIST")))

;; ── ListObjectsV2 response ───────────────────────────────────────────────────
;;
;; A deliberately shallow extractor, not an XML parser. S3's ListObjectsV2 body
;; is a flat, fixed shape, and pulling four element types out of it with regexes
;; is honest about what it does — whereas shipping a general XML parser (or a
;; per-runtime dependency on one) would be a much larger promise than this
;; library needs to keep. If you need the full document, parse `:body` yourself.

(defn- unescape-xml [s]
  (-> s
      (str/replace #"&#x([0-9A-Fa-f]+);"
                   (fn [m] (str (char #?(:clj  (Integer/parseInt (second m) 16)
                                         :cljs (js/parseInt (second m) 16))))))
      (str/replace #"&#(\d+);"
                   (fn [m] (str (char #?(:clj  (Integer/parseInt (second m))
                                         :cljs (js/parseInt (second m) 10))))))
      (str/replace "&lt;" "<")
      (str/replace "&gt;" ">")
      (str/replace "&quot;" "\"")
      (str/replace "&apos;" "'")
      ;; &amp; last, so "&amp;lt;" decodes to the literal "&lt;" and not "<"
      (str/replace "&amp;" "&")))

(defn- tag-values [xml tag]
  (map (comp unescape-xml second)
       (re-seq (re-pattern (str "<" tag ">([^<]*)</" tag ">")) xml)))

(defn parse-list-result
  "Extract the useful fields from a ListObjectsV2 body →

      {:keys [\"a.txt\" …]
       :common-prefixes [\"dir/\" …]
       :truncated? false
       :next-continuation-token nil}

  `:keys` are the `<Contents><Key>` entries; `:common-prefixes` the directory
  rollups produced by `:delimiter`."
  [xml]
  (let [xml (str xml)
        contents (re-seq #"(?s)<Contents>(.*?)</Contents>" xml)]
    {:keys (mapcat #(tag-values (second %) "Key") contents)
     :common-prefixes (mapcat #(tag-values (second %) "Prefix")
                              (re-seq #"(?s)<CommonPrefixes>(.*?)</CommonPrefixes>" xml))
     :truncated? (= "true" (first (tag-values xml "IsTruncated")))
     :next-continuation-token (first (tag-values xml "NextContinuationToken"))}))
