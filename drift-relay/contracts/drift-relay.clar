;; drift-relay.clar
;; Drift-Relay: Decentralized Shipping Verification Network

;; CONSTANTS

(define-constant CONTRACT-OWNER tx-sender)

;; Roles
(define-constant ROLE-CARRIER     u1)
(define-constant ROLE-WAREHOUSE   u2)
(define-constant ROLE-CUSTOMS     u3)
(define-constant ROLE-RECEIVER    u4)

;; Shipment statuses
(define-constant STATUS-REGISTERED  u0)
(define-constant STATUS-IN-TRANSIT  u1)
(define-constant STATUS-DELIVERED   u2)
(define-constant STATUS-DISPUTED    u3)
(define-constant STATUS-CANCELLED   u4)

;; Sensor alert types
(define-constant ALERT-TEMPERATURE  u1)
(define-constant ALERT-HUMIDITY     u2)
(define-constant ALERT-SHOCK        u3)
(define-constant ALERT-TAMPER       u4)
(define-constant ALERT-ROUTE-DRIFT  u5)

;; Error codes
(define-constant ERR-NOT-AUTHORIZED        (err u100))
(define-constant ERR-SHIPMENT-NOT-FOUND    (err u101))
(define-constant ERR-ALREADY-EXISTS        (err u102))
(define-constant ERR-INVALID-STATUS        (err u103))
(define-constant ERR-INVALID-ROLE          (err u104))
(define-constant ERR-ALREADY-SIGNED        (err u105))
(define-constant ERR-CONDITION-BREACH      (err u106))
(define-constant ERR-INSUFFICIENT-FUNDS    (err u107))
(define-constant ERR-INVALID-PARAMS        (err u108))

;; ============================================================
;; DATA MAPS AND VARIABLES
;; ============================================================

;; Global shipment counter
(define-data-var shipment-nonce uint u0)

;; Registered network participants (validators)
;; Maps principal => role
(define-map validators
  principal
  { role: uint, active: bool, registered-at: uint })

;; Core shipment record (digital passport)
(define-map shipments
  uint  ;; shipment-id
  {
    shipper:          principal,
    receiver:         principal,
    carrier:          principal,
    origin:           (string-ascii 64),
    destination:      (string-ascii 64),
    cargo-hash:       (buff 32),       ;; SHA-256 of cargo manifest
    status:           uint,
    payment-amount:   uint,            ;; in microSTX
    payment-released: bool,
    insurance-amount: uint,            ;; in microSTX
    claim-triggered:  bool,
    created-at:       uint,
    updated-at:       uint,
    ;; Compliance thresholds
    max-temp:         int,             ;; Celsius * 100 (fixed-point)
    min-temp:         int,
    max-humidity:     uint,            ;; Percent * 100
    max-shock-g:      uint,            ;; G-force * 100
    tamper-allowed:   bool
  })

;; Proof-of-Transit signatures per shipment
;; Maps (shipment-id, validator) => signature record
(define-map transit-signatures
  { shipment-id: uint, validator: principal }
  {
    role:       uint,
    signed-at:  uint,
    checkpoint: (string-ascii 64),
    data-hash:  (buff 32)
  })

;; Sensor readings log
;; Maps (shipment-id, reading-index) => sensor data
(define-map sensor-readings
  { shipment-id: uint, index: uint }
  {
    recorder:    principal,
    temperature: int,     ;; Celsius * 100
    humidity:    uint,    ;; Percent * 100
    shock-g:     uint,    ;; G-force * 100
    tampered:    bool,
    latitude:    int,     ;; Degrees * 1000000
    longitude:   int,     ;; Degrees * 1000000
    recorded-at: uint
  })

;; Reading count per shipment
(define-map reading-count uint uint)

;; Alerts log per shipment
;; Maps (shipment-id, alert-index) => alert
(define-map alerts
  { shipment-id: uint, index: uint }
  {
    alert-type:  uint,
    description: (string-ascii 128),
    triggered-at: uint,
    resolved:    bool
  })

(define-map alert-count uint uint)

;; Signature count per shipment (for quorum tracking)
(define-map signature-count uint uint)

;; ============================================================
;; PRIVATE HELPERS
;; ============================================================

(define-private (is-owner)
  (is-eq tx-sender CONTRACT-OWNER))

(define-private (is-validator (addr principal))
  (match (map-get? validators addr)
    v (get active v)
    false))

(define-private (get-validator-role (addr principal))
  (match (map-get? validators addr)
    v (get role v)
    u0))

(define-private (shipment-exists (id uint))
  (is-some (map-get? shipments id)))

(define-private (get-reading-index (id uint))
  (default-to u0 (map-get? reading-count id)))

(define-private (get-alert-index (id uint))
  (default-to u0 (map-get? alert-count id)))

(define-private (get-sig-count (id uint))
  (default-to u0 (map-get? signature-count id)))

;; Check if a sensor reading violates compliance thresholds
(define-private (check-compliance
    (id uint)
    (temp int)
    (humidity uint)
    (shock uint)
    (tampered bool))
  (match (map-get? shipments id)
    s (and
        (>= temp (get min-temp s))
        (<= temp (get max-temp s))
        (<= humidity (get max-humidity s))
        (<= shock (get max-shock-g s))
        (or (not tampered) (get tamper-allowed s)))
    false))

;; Record an alert
(define-private (record-alert
    (id uint)
    (alert-type uint)
    (description (string-ascii 128)))
  (let ((idx (get-alert-index id)))
    (map-set alerts
      { shipment-id: id, index: idx }
      { alert-type:    alert-type,
        description:   description,
        triggered-at:  block-height,
        resolved:      false })
    (map-set alert-count id (+ idx u1))))

;; ============================================================
;; VALIDATOR MANAGEMENT
;; ============================================================

;; Register a new network validator/participant
(define-public (register-validator (addr principal) (role uint))
  (begin
    (asserts! (is-owner) ERR-NOT-AUTHORIZED)
    (asserts! (and (>= role u1) (<= role u4)) ERR-INVALID-ROLE)
    (asserts! (is-none (map-get? validators addr)) ERR-ALREADY-EXISTS)
    (map-set validators addr
      { role:          role,
        active:        true,
        registered-at: block-height })
    (ok true)))

;; Deactivate a validator
(define-public (deactivate-validator (addr principal))
  (begin
    (asserts! (is-owner) ERR-NOT-AUTHORIZED)
    (asserts! (is-some (map-get? validators addr)) ERR-NOT-AUTHORIZED)
    (map-set validators addr
      (merge (unwrap-panic (map-get? validators addr))
             { active: false }))
    (ok true)))

;; ============================================================
;; SHIPMENT LIFECYCLE
;; ============================================================

;; Register a new shipment and lock payment escrow
(define-public (register-shipment
    (receiver   principal)
    (carrier    principal)
    (origin     (string-ascii 64))
    (destination (string-ascii 64))
    (cargo-hash (buff 32))
    (payment    uint)
    (insurance  uint)
    (max-temp   int)
    (min-temp   int)
    (max-humidity uint)
    (max-shock-g  uint)
    (tamper-allowed bool))
  (let ((id (+ (var-get shipment-nonce) u1)))
    (asserts! (> (len origin) u0) ERR-INVALID-PARAMS)
    (asserts! (> (len destination) u0) ERR-INVALID-PARAMS)
    (asserts! (> (len cargo-hash) u0) ERR-INVALID-PARAMS)
    ;; Lock payment + insurance in contract escrow
    (asserts!
      (>= (stx-get-balance tx-sender) (+ payment insurance))
      ERR-INSUFFICIENT-FUNDS)
    (try! (stx-transfer? (+ payment insurance) tx-sender (as-contract tx-sender)))
    (map-set shipments id
      { shipper:          tx-sender,
        receiver:         receiver,
        carrier:          carrier,
        origin:           origin,
        destination:      destination,
        cargo-hash:       cargo-hash,
        status:           STATUS-REGISTERED,
        payment-amount:   payment,
        payment-released: false,
        insurance-amount: insurance,
        claim-triggered:  false,
        created-at:       block-height,
        updated-at:       block-height,
        max-temp:         max-temp,
        min-temp:         min-temp,
        max-humidity:     max-humidity,
        max-shock-g:      max-shock-g,
        tamper-allowed:   tamper-allowed })
    (var-set shipment-nonce id)
    (ok id)))

;; Carrier activates transit
(define-public (start-transit (id uint))
  (begin
    (asserts! (shipment-exists id) ERR-SHIPMENT-NOT-FOUND)
    (let ((s (unwrap-panic (map-get? shipments id))))
      (asserts! (is-eq tx-sender (get carrier s)) ERR-NOT-AUTHORIZED)
      (asserts! (is-eq (get status s) STATUS-REGISTERED) ERR-INVALID-STATUS)
      (map-set shipments id
        (merge s { status: STATUS-IN-TRANSIT, updated-at: block-height }))
      (ok true))))

;; ============================================================
;; PROOF-OF-TRANSIT: VALIDATOR SIGNATURES
;; ============================================================

;; Submit a checkpoint signature (Proof-of-Transit)
(define-public (sign-checkpoint
    (id         uint)
    (checkpoint (string-ascii 64))
    (data-hash  (buff 32)))
  (begin
    (asserts! (shipment-exists id) ERR-SHIPMENT-NOT-FOUND)
    (asserts! (is-validator tx-sender) ERR-NOT-AUTHORIZED)
    (asserts!
      (is-none (map-get? transit-signatures
        { shipment-id: id, validator: tx-sender }))
      ERR-ALREADY-SIGNED)
    (let ((role (get-validator-role tx-sender))
          (cnt  (get-sig-count id)))
      (map-set transit-signatures
        { shipment-id: id, validator: tx-sender }
        { role:       role,
          signed-at:  block-height,
          checkpoint: checkpoint,
          data-hash:  data-hash })
      (map-set signature-count id (+ cnt u1))
      (ok true))))

;; ============================================================
;; IOT SENSOR DATA RECORDING
;; ============================================================

;; Record a sensor reading from an IoT device / validator
;; Automatically checks compliance and fires alerts
(define-public (record-sensor-data
    (id          uint)
    (temperature int)
    (humidity    uint)
    (shock-g     uint)
    (tampered    bool)
    (latitude    int)
    (longitude   int))
  (begin
    (asserts! (shipment-exists id) ERR-SHIPMENT-NOT-FOUND)
    (asserts! (is-validator tx-sender) ERR-NOT-AUTHORIZED)
    (let ((s   (unwrap-panic (map-get? shipments id)))
          (idx (get-reading-index id)))
      (asserts! (is-eq (get status s) STATUS-IN-TRANSIT) ERR-INVALID-STATUS)
      ;; Store sensor reading
      (map-set sensor-readings
        { shipment-id: id, index: idx }
        { recorder:    tx-sender,
          temperature: temperature,
          humidity:    humidity,
          shock-g:     shock-g,
          tampered:    tampered,
          latitude:    latitude,
          longitude:   longitude,
          recorded-at: block-height })
      (map-set reading-count id (+ idx u1))
      ;; Compliance checks - record alerts for each breach
      (let ((temp-ok
              (and (>= temperature (get min-temp s))
                   (<= temperature (get max-temp s))))
            (hum-ok  (<= humidity (get max-humidity s)))
            (shock-ok (<= shock-g (get max-shock-g s)))
            (tamper-ok (or (not tampered) (get tamper-allowed s))))
        (if (not temp-ok)
          (record-alert id ALERT-TEMPERATURE
            "Temperature out of compliance range")
          false)
        (if (not hum-ok)
          (record-alert id ALERT-HUMIDITY
            "Humidity out of compliance range")
          false)
        (if (not shock-ok)
          (record-alert id ALERT-SHOCK
            "Shock G-force exceeded threshold")
          false)
        (if (not tamper-ok)
          (record-alert id ALERT-TAMPER
            "Tamper event detected on shipment")
          false)
        (ok true)))))

;; ============================================================
;; DRIFT DETECTION
;; ============================================================

;; Flag a route or condition anomaly (drift detection)
;; Called by off-chain ML oracle or validator
(define-public (report-drift
    (id          uint)
    (description (string-ascii 128)))
  (begin
    (asserts! (shipment-exists id) ERR-SHIPMENT-NOT-FOUND)
    (asserts! (is-validator tx-sender) ERR-NOT-AUTHORIZED)
    (let ((s (unwrap-panic (map-get? shipments id))))
      (asserts! (is-eq (get status s) STATUS-IN-TRANSIT) ERR-INVALID-STATUS)
      (record-alert id ALERT-ROUTE-DRIFT description)
      (ok true))))

;; ============================================================
;; DELIVERY AND PAYMENT SETTLEMENT
;; ============================================================

;; Receiver confirms delivery - triggers payment release
(define-public (confirm-delivery (id uint))
  (begin
    (asserts! (shipment-exists id) ERR-SHIPMENT-NOT-FOUND)
    (let ((s (unwrap-panic (map-get? shipments id))))
      (asserts! (is-eq tx-sender (get receiver s)) ERR-NOT-AUTHORIZED)
      (asserts! (is-eq (get status s) STATUS-IN-TRANSIT) ERR-INVALID-STATUS)
      (asserts! (not (get payment-released s)) ERR-INVALID-STATUS)
      ;; Release carrier payment
      (try! (as-contract
        (stx-transfer?
          (get payment-amount s)
          tx-sender
          (get carrier s))))
      ;; Return unused insurance to shipper
      (try! (as-contract
        (stx-transfer?
          (get insurance-amount s)
          tx-sender
          (get shipper s))))
      (map-set shipments id
        (merge s
          { status:           STATUS-DELIVERED,
            payment-released: true,
            updated-at:       block-height }))
      (ok true))))

;; Trigger insurance claim on condition breach
;; Can be called by shipper after a tamper/condition alert
(define-public (trigger-insurance-claim (id uint))
  (begin
    (asserts! (shipment-exists id) ERR-SHIPMENT-NOT-FOUND)
    (let ((s     (unwrap-panic (map-get? shipments id)))
          (n-alerts (get-alert-index id)))
      (asserts! (is-eq tx-sender (get shipper s)) ERR-NOT-AUTHORIZED)
      (asserts! (not (get claim-triggered s)) ERR-INVALID-STATUS)
      ;; Require at least one active alert to file a claim
      (asserts! (> n-alerts u0) ERR-INVALID-STATUS)
      ;; Pay insurance payout to shipper
      (try! (as-contract
        (stx-transfer?
          (get insurance-amount s)
          tx-sender
          (get shipper s))))
      (map-set shipments id
        (merge s
          { claim-triggered: true,
            status:          STATUS-DISPUTED,
            updated-at:      block-height }))
      (ok true))))

;; Cancel a shipment before transit begins (refunds shipper)
(define-public (cancel-shipment (id uint))
  (begin
    (asserts! (shipment-exists id) ERR-SHIPMENT-NOT-FOUND)
    (let ((s (unwrap-panic (map-get? shipments id))))
      (asserts! (is-eq tx-sender (get shipper s)) ERR-NOT-AUTHORIZED)
      (asserts! (is-eq (get status s) STATUS-REGISTERED) ERR-INVALID-STATUS)
      ;; Refund full escrow to shipper
      (try! (as-contract
        (stx-transfer?
          (+ (get payment-amount s) (get insurance-amount s))
          tx-sender
          (get shipper s))))
      (map-set shipments id
        (merge s { status: STATUS-CANCELLED, updated-at: block-height }))
      (ok true))))

;; ============================================================
;; READ-ONLY QUERIES
;; ============================================================

;; Get shipment digital passport
(define-read-only (get-shipment (id uint))
  (map-get? shipments id))

;; Get a specific sensor reading
(define-read-only (get-sensor-reading (id uint) (index uint))
  (map-get? sensor-readings { shipment-id: id, index: index }))

;; Get total sensor readings for a shipment
(define-read-only (get-reading-count (id uint))
  (default-to u0 (map-get? reading-count id)))

;; Get a specific alert
(define-read-only (get-alert (id uint) (index uint))
  (map-get? alerts { shipment-id: id, index: index }))

;; Get total alerts for a shipment
(define-read-only (get-alert-count (id uint))
  (default-to u0 (map-get? alert-count id)))

;; Get Proof-of-Transit signature for a validator on a shipment
(define-read-only (get-signature (id uint) (validator principal))
  (map-get? transit-signatures { shipment-id: id, validator: validator }))

;; Get total PoT signatures collected for a shipment
(define-read-only (get-signature-count (id uint))
  (default-to u0 (map-get? signature-count id)))

;; Get validator info
(define-read-only (get-validator (addr principal))
  (map-get? validators addr))

;; Get latest shipment ID
(define-read-only (get-shipment-nonce)
  (var-get shipment-nonce))
