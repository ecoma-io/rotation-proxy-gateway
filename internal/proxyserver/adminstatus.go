package proxyserver

import (
	"encoding/json"
	"net/http"
	"time"

	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/warmpool"
)

// The /status three-scope split.
//
// An operator reading one status document is reading three different things at
// once, and conflating them is how a single-node deployment reads as a healthy
// cluster. Each figure below is labelled with the scope that owns it:
//
//   - cluster      — durable, shared state every replica must agree on: the
//     configuration revision this instance is serving, and the durable store's
//     own view when one is configured. Shared truth; losing it is an outage.
//   - distributed  — runtime state meaningful only in aggregate across replicas:
//     request and failover counters, global rotation counts. Each instance's
//     slice is local, but the number an operator wants is the sum, so a single
//     figure here must never be read as the fleet's.
//   - instance     — this process alone, and meaningless to any other replica:
//     version, uptime, warm-pool occupancy, per-route health.
//
// The top-level keys stay exactly where they were. `version`, `requests`,
// `failovers`, `listeners`, `pool`, `rotations`, `ipRevisits`, `warmPool`, and
// `configRevision` are a published wire contract that six test files and the
// e2e suite decode positionally, and this build ships one at a time. The scope
// objects below are added alongside them, so a client that wants the new
// grouping gets it and a client that reads the old flat shape keeps working.
// What changed for the reader is not the numbers but their labelling: every
// field now also appears under its scope, and each scope object names itself in
// `scope` so a client can tell a grouping from a resource.
//
// The labels are also the answer to "which of these numbers is a lie when there
// is one replica?": `requests` is a distributed-runtime total that happens to
// be exactly right on one node and silently wrong on two, and only its label
// says so.

// ScopeCluster identifies state that is durable and shared by every replica.
const ScopeCluster = "cluster"

// ScopeDistributed identifies runtime state that is only meaningful summed
// across replicas.
const ScopeDistributed = "distributed"

// ScopeInstance identifies state that belongs to this process alone.
const ScopeInstance = "instance"

// ClusterStatus is the cluster/durable scope of /status.
//
// Everything here is either durable or read from the instance's cached view of
// the durable store. It never costs a control-database query per request: the
// caller refreshes a snapshot on its own reconcile cadence and hands this
// function a copy, because /status is unauthenticated and a per-request query
// would let any caller amplify load on the control database.
type ClusterStatus struct {
	// ConfigRevision is the durable revision this instance is serving. Zero
	// means this instance runs on its local seed configuration rather than on a
	// committed revision — a real state, reported as zero for backward
	// compatibility rather than hidden.
	ConfigRevision int64 `json:"configRevision"`
	// StoreConfigured reports whether a durable store is wired at all. False is
	// a supported deployment (file-seeded, single instance), not a fault.
	StoreConfigured bool `json:"storeConfigured"`
	// ActiveRevision is the revision the durable store's pointer names, or zero
	// when unknown or when no store is configured. It is a cached observation
	// and may lag ConfigRevision while this instance converges.
	ActiveRevision int64 `json:"activeRevision"`
	// Synced reports whether ActiveRevision equals ConfigRevision — that is,
	// whether this instance is serving what the cluster points at. False during
	// a normal convergence window, and it is the one field here that says
	// "this replica is behind".
	Synced bool `json:"synced"`
}

// writeStatus emits the /status document.
//
// Every field is built here explicitly rather than reflected from the pool
// snapshot, so adding a scope is a deliberate act: a new health counter becomes
// instance-scoped because someone said so, not because it appeared on a struct.
func writeStatus(w http.ResponseWriter, version string, started time.Time, store *pool.Store, listeners map[string]*Server, rotations func() uint64, ipRevisits func() uint64, warm func() warmpool.Status, cluster ClusterStatus) {
	w.Header().Set("Content-Type", "application/json")
	// Operational state and pool health describe a moving target, and /status is
	// unauthenticated: a cached copy would be a wrong answer served as a right
	// one. No-store is the honest header for a snapshot.
	w.Header().Set("Cache-Control", "no-store")

	perListener := make(map[string]ListenerStatus, len(listeners))
	var requests, failovers uint64
	for name, listener := range listeners {
		status := listener.ListenerStatus()
		perListener[name] = status
		requests += status.Requests
		failovers += status.Failovers
	}
	gen := store.Load()

	status := map[string]any{
		// The revision is read from the generation /status already loads, so
		// reporting it costs no query against the control database and cannot
		// drift from what is serving.
		"version":        version,
		"uptime":         time.Since(started).Truncate(time.Second).String(),
		"requests":       requests,
		"failovers":      failovers,
		"listeners":      perListener,
		"pool":           gen.Pool.Snapshot(),
		"configRevision": gen.ConfigRevision,
	}

	distributed := map[string]any{
		"scope":     ScopeDistributed,
		"requests":  requests,
		"failovers": failovers,
	}
	if rotations != nil {
		status["rotations"] = rotations()
		distributed["rotations"] = rotations()
	}
	if ipRevisits != nil {
		status["ipRevisits"] = ipRevisits()
		distributed["ipRevisits"] = ipRevisits()
	}

	instance := map[string]any{
		"scope":   ScopeInstance,
		"version": version,
		"uptime":  time.Since(started).Truncate(time.Second).String(),
		"pool":    gen.Pool.Snapshot(),
	}
	if warm != nil {
		status["warmPool"] = warm()
		instance["warmPool"] = warm()
	}

	status["cluster"] = map[string]any{
		"scope":           ScopeCluster,
		"configRevision":  cluster.ConfigRevision,
		"storeConfigured": cluster.StoreConfigured,
		"activeRevision":  cluster.ActiveRevision,
		"synced":          cluster.Synced,
	}
	status["distributed"] = distributed
	status["instance"] = instance

	_ = json.NewEncoder(w).Encode(status)
}
