(ns storj.store
  "The four functions a content-addressed consumer wants, over a bucket.

  `storj.core` is shaped for S3: keys, ranges, content types, response maps,
  404 as a status rather than a value. A consumer that only wants *bytes by
  reference* has to translate all of that, and every one of them translates it
  slightly differently — which for the 404 case means some of them cannot tell
  `this object is gone` from `this request failed`.

  So the translation is here, once. What comes back is a plain map:

      {:get-object f :put-object f :delete-object f :exists? f}

  and nothing in this namespace names who consumes it. `kotoba-lang/drive`'s
  `drive.object/store-of` takes exactly this shape, and neither library
  depends on the other — whoever builds the store depends on both, and that is
  the application.

  ## A clock has to be handed in

  `storj.core/sign` reads no clock on purpose: a signer that took the time
  from the machine cannot be tested against AWS's own vectors, which are all
  fixed instants. Defaulting to a system clock here would undo that one layer
  up, so `:now` is a required function. It returns an ISO-8601 instant
  (`20130524T000000Z` style, whatever `sign` accepts).

  ## Bytes are a vector of unsigned ints

  Both ways, unconditionally. `storj.core` signs a byte array and returns
  whatever the transport handed it; `drive.object` and every other byte
  handling in this workspace passes vectors of 0-255. Converting at one edge
  rather than at every call site is the point of this namespace — and it is a
  contract rather than a convenience, so a caller who wants the S3 shapes uses
  `storj.core` directly, which is what it is for.

  ## Synchronous on the JVM, thenable on JS

  `storj.core`'s `then` is identity application on `:clj` and `.then` on
  `:cljs`, so these functions return values on a JVM and promises in a
  browser. A consumer whose own interface is synchronous — `drive.object` is,
  because a workspace is a value and its permission checks are pure — can use
  these directly on a JVM and needs its own boundary on JS. Said here rather
  than discovered there."
  (:require [storj.core :as core]))

(defn- fail [msg data]
  (throw (ex-info (str "storj.store: " msg) data)))

(defn- then
  "The same sync/async duality `storj.core` has, for the one place here that
  needs to look at what a call returned. Duplicated rather than exported from
  there because it is three lines and exporting it would make the duality part
  of that namespace's public shape."
  [v f]
  #?(:clj  (f v)
     :cljs (.then (js/Promise.resolve v) f)))

(defn- ->bytes
  "A vector of unsigned ints → what the signer can hash.

  Strings and existing byte containers pass through: a caller handing this a
  string means a string, and re-encoding one would change what was signed."
  [body]
  (cond
    (string? body) body
    (sequential? body) #?(:clj  (byte-array (map unchecked-byte body))
                          :cljs (js/Uint8Array.from (into-array body)))
    :else body))

(defn- ->ints
  "Whatever the transport returned → a vector of unsigned ints."
  [body]
  (when (some? body)
    (if (sequential? body)
      (vec body)
      (mapv #(bit-and (int %) 0xff) (seq body)))))

(defn object-key
  "The S3 key an object reference becomes.

  A prefix keeps one consumer's objects from colliding with anything else in
  the bucket. It is not a security boundary — a credential that can read the
  prefix can read the bucket — and is not treated as one anywhere here."
  [prefix ref]
  (when-not (string? ref)
    (fail "an object reference is a string" {:object-ref ref}))
  (if (seq prefix) (str prefix ref) ref))

(defn store-fns
  "Turn a `storj.core` client into the four functions.

      (store-fns client {:now #(iso-now) :prefix \"drive/acme/\"})

  `:now` is required — see the namespace docstring. `:content-type` is what
  `put-object` signs when the caller has nothing better; a store addressed by
  reference usually does not know what the bytes are, and saying
  `application/octet-stream` is more honest than guessing from the key."
  [client {:keys [now prefix content-type]
           :or   {content-type "application/octet-stream"}}]
  (when-not (fn? now)
    (fail "a clock function is required — the signer deliberately has none" {}))
  {:get-object
   (fn [ref]
     ;; `get-object` is nil on 404 and a response otherwise, so the body comes
     ;; out *after* that distinction. Pulling `:body` first would make a
     ;; missing object and an empty one the same answer, and a consumer
     ;; deciding whether its own records are wrong needs to tell them apart.
     (then (core/get-object client {:key (object-key prefix ref) :now (now)})
           #(some-> % :body ->ints)))

   :put-object
   (fn [ref bytes]
     (core/put-object client {:key (object-key prefix ref) :body (->bytes bytes)
                              :now (now) :content-type content-type}))

   :delete-object
   (fn [ref]
     (core/delete-object client {:key (object-key prefix ref) :now (now)}))

   :exists?
   (fn [ref]
     (then (core/head-object client {:key (object-key prefix ref) :now (now)})
           some?))})
