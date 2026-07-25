#!/usr/bin/env nbb
;; verify-cljs.cljs — two-runtime parity check.
;;
;; `clojure -M:test` proves the library on the JVM, where `storj.core/then` is
;; identity-application and every crypto call returns a value. That leaves the
;; half that actually ships to browsers and Workers untested: WebCrypto is
;; Promise-based, so the *same* code takes a completely different path through
;; `then`. A green JVM suite says nothing about it.
;;
;; So this script re-runs the load-bearing assertions — AWS's two published
;; reference signatures, and the request/presign signatures cross-checked
;; against an independent implementation in `core_test` — through nbb, on
;; crypto.subtle. Identical expected values, different runtime. If the async
;; composition in `then` were wrong, these would fail while the JVM suite
;; stayed green.
;;
;;   nbb scripts/verify-cljs.cljs

(require '[clojure.string :as str]
         '[storj.core :as storj]
         '[storj.crypto :as crypto]
         '[storj.protocols :as p]
         '[storj.sigv4 :as v4])

(def failures (atom 0))

(defn check [label expected actual]
  (if (= expected actual)
    (println "  ok  " label)
    (do (swap! failures inc)
        (println "  FAIL" label)
        (println "        expected:" (pr-str expected))
        (println "        actual:  " (pr-str actual)))))

(def c (crypto/crypto))

(def aws-secret "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

(defn signing-key
  "Fold the HMAC ladder over Promises — the async mirror of the JVM reduce."
  [secret short region]
  (let [{:keys [secret steps]} (v4/signing-key-chain secret short region)]
    (reduce (fn [p step] (.then p #(p/-hmac c % step)))
            (js/Promise.resolve secret)
            steps)))

(defn sign-string [secret short region sts]
  (-> (signing-key secret short region)
      (.then #(p/-hmac c % sts))
      (.then #(p/-hex c %))))

;; ── 1. WebCrypto digests agree with the JVM's ────────────────────────────────
(defn check-digests []
  (js/Promise.all
   #js [(.then (p/-sha256-hex c "") #(check "sha256 of empty string" v4/empty-payload-sha256 %))
        (.then (p/-sha256-hex c "hello")
               #(check "sha256 of \"hello\""
                       "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" %))
        (.then (p/-sha256-hex c "日本語")
               #(check "sha256 is UTF-8, not UTF-16"
                       "77710aedc74ecfa33685e33a6c7df5cc83004da1bdcef7fb280f5c2b2e97e0a5" %))]))

;; ── 2. AWS's published header-auth signature ─────────────────────────────────
(defn check-aws-header-vector []
  (let [canonical (str "GET\n/test.txt\n\n"
                       "host:examplebucket.s3.amazonaws.com\n"
                       "range:bytes=0-9\n"
                       "x-amz-content-sha256:" v4/empty-payload-sha256 "\n"
                       "x-amz-date:20130524T000000Z\n\n"
                       "host;range;x-amz-content-sha256;x-amz-date\n"
                       v4/empty-payload-sha256)]
    (-> (p/-sha256-hex c canonical)
        (.then (fn [cr-hash]
                 (check "AWS canonical-request hash"
                        "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972" cr-hash)
                 (sign-string aws-secret "20130524" "us-east-1"
                              (v4/string-to-sign "20130524T000000Z"
                                                 (v4/credential-scope "20130524" "us-east-1")
                                                 cr-hash))))
        (.then #(check "AWS documented header-auth signature"
                       "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41" %)))))

;; ── 3. AWS's published query-string-auth signature ───────────────────────────
(defn check-aws-presign-vector []
  (let [scope (v4/credential-scope "20130524" "us-east-1")
        qs    (v4/canonical-query
               (v4/presign-params {:key-id          "AKIAIOSFODNN7EXAMPLE"
                                   :scope           scope
                                   :long-date       "20130524T000000Z"
                                   :expires-seconds 86400
                                   :signed-headers  "host"}))
        cr    (:canonical-request
               (v4/canonical-request {:method       :get
                                      :path         "/test.txt"
                                      :query        qs
                                      :headers      {"host" "examplebucket.s3.amazonaws.com"}
                                      :payload-hash v4/unsigned-payload}))]
    (-> (p/-sha256-hex c cr)
        (.then #(sign-string aws-secret "20130524" "us-east-1"
                             (v4/string-to-sign "20130524T000000Z" scope %)))
        (.then #(check "AWS documented query-string-auth signature"
                       "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404" %)))))

;; ── 4. The full client, on the same vectors core_test uses ───────────────────
(defrecord CapturingHttp [sent]
  p/IHttp
  (-request [_ req] (reset! sent req) #js {}))

(def now "2026-07-25T12:00:00.000Z")

(defn- signature-of [req]
  (second (re-find #"Signature=([0-9a-f]+)" (get-in req [:headers "authorization"]))))

(defn check-client []
  (let [sent   (atom nil)
        client (storj/client {:bucket "my-bucket" :access-key "jwtest" :secret-key "supersecret"}
                             {:crypto c :http (->CapturingHttp sent)})]
    (-> (storj/sign client {:method :get :key "docs/readme.txt" :now now})
        (.then (fn [req]
                 (check "signed GET url"
                        "https://gateway.storjshare.io/my-bucket/docs/readme.txt" (:url req))
                 (check "signed GET signature (matches JVM + independent impl)"
                        "2f164e6a8b8805003436d9150ca22b2ed89f4bdcfa505bb0bcfe36d42d2ca528"
                        (signature-of req))))
        (.then (fn [_] (storj/sign client {:method :put :key "docs/readme.txt"
                                           :body "hello storj" :now now
                                           :headers {"content-type" "text/plain"}})))
        (.then (fn [req]
                 (check "PUT body hash"
                        "275a8f4e11cbf657431976aba8402192cd60919fede551e0a9bc59ea001a43bf"
                        (get-in req [:headers "x-amz-content-sha256"]))
                 (check "signed PUT signature"
                        "b1433226d0b4bd5f58abdba0d533a353997dca3ab90bf3fdee6aa43c7527cf6b"
                        (signature-of req))))
        (.then (fn [_] (storj/presign client {:key "docs/readme.txt" :now now})))
        (.then (fn [url]
                 (check "presigned URL"
                        (str "https://gateway.storjshare.io/my-bucket/docs/readme.txt"
                             "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
                             "&X-Amz-Credential=jwtest%2F20260725%2Fus-east-1%2Fs3%2Faws4_request"
                             "&X-Amz-Date=20260725T120000Z"
                             "&X-Amz-Expires=3600"
                             "&X-Amz-SignedHeaders=host"
                             "&X-Amz-Signature=8890b75c4127c944b41ade4dcacb46afd437ab9ce89678bf3d9139c9e1b78fb9")
                        url))))))

;; ── 5. Pure layer, unchanged across runtimes ─────────────────────────────────
(defn check-pure []
  (check "uri-encode does not exempt !'()*" "%21%27%28%29%2A" (v4/uri-encode "!'()*"))
  (check "uri-encode emits UTF-8 bytes" "%E6%97%A5" (v4/uri-encode "日"))
  (check "object-path keeps separators" "/b/a%20b/c.txt" (v4/object-path "b" "a b/c.txt"))
  (check "list result parsing"
         ["docs/b & c.txt"]
         (:keys (storj/parse-list-result "<Contents><Key>docs/b &amp; c.txt</Key></Contents>")))
  (js/Promise.resolve nil))

(println "storj — ClojureScript / WebCrypto parity check (nbb)\n")
(-> (js/Promise.resolve nil)
    (.then check-pure)
    (.then check-digests)
    (.then check-aws-header-vector)
    (.then check-aws-presign-vector)
    (.then check-client)
    (.then (fn [_]
             (println)
             (if (zero? @failures)
               (println "all checks passed on the ClojureScript path")
               (do (println @failures "check(s) FAILED")
                   (set! (.-exitCode js/process) 1)))))
    (.catch (fn [e]
              (println "verification threw:" (str/trim (str (or (.-stack e) e))))
              (set! (.-exitCode js/process) 1))))
