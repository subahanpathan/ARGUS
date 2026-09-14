/**
 * UniverseEventTimeline — live feed of connection lifecycle events.
 * Shows real NEW, CLOSED, and STATE_CHANGE events from the telemetry pipeline.
 */

import type { TopologyConnectionEvent } from "@/hooks/use-network-topology";

function fmtWhen(iso: string | undefined): string {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleTimeString(); } catch { return "—"; }
}

function EventBadge({ type }: { type: string }) {
  const cls = type === "NEW" ? "badge-low"
    : type === "CLOSED" ? "badge-high"
    : type === "GATEWAY_CHANGE" || type === "DNS_CHANGE" ? "badge-medium"
    : type === "INTERFACE_UP" ? "badge-low"
    : type === "INTERFACE_DOWN" ? "badge-high"
    : "badge-muted";
  return <span className={`badge ${cls}`}>{type}</span>;
}

export function UniverseEventTimeline({
  events,
  isLive,
  maxEvents = 50,
}: {
  events: TopologyConnectionEvent[];
  isLive: boolean;
  maxEvents?: number;
}) {
  const visible = events.slice(-maxEvents).reverse();

  return (
    <div data-testid="universe-event-timeline">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 700 }}>Live Network Activity</div>
          <div className="mono muted" style={{ fontSize: 10 }}>
            {isLive ? `${events.length} events this session` : "No live events"}
          </div>
        </div>
        {isLive && (
          <span className="badge badge-low" style={{ background: "hsl(142 71% 20%)", color: "hsl(142 71% 70%)", border: "1px solid hsl(142 71% 30%)" }}>
            STREAMING
          </span>
        )}
      </div>

      <div style={{ maxHeight: 280, overflowY: "auto" }}>
        {visible.length === 0 ? (
          <div className="empty" style={{ padding: 24 }}>
            <h3>{isLive ? "Waiting for events..." : "No events"}</h3>
            <p>{isLive ? "Connection lifecycle events will appear here." : "Start the security engine to see live network events."}</p>
          </div>
        ) : (
          visible.map((evt, i) => (
            <div
              key={`${evt.timestamp}-${evt.pid}-${evt.remote_addr}-${evt.remote_port}-${i}`}
              className="event-row"
            >
              <div
                className="event-dot"
                style={{
                  background: evt.event_type === "NEW"
                    ? "hsl(var(--accent))"
                    : evt.event_type === "CLOSED"
                    ? "hsl(var(--destructive))"
                    : evt.event_type === "GATEWAY_CHANGE" || evt.event_type === "DNS_CHANGE"
                    ? "hsl(var(--chart-5))"
                    : evt.event_type === "INTERFACE_UP"
                    ? "hsl(142 71% 55%)"
                    : evt.event_type === "INTERFACE_DOWN"
                    ? "hsl(0 72% 55%)"
                    : "hsl(var(--chart-3))",
                  boxShadow: "none",
                }}
              />
              <div className="event-copy">
                <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 3 }}>
                  <EventBadge type={evt.event_type || "—"} />
                  <span className="mono" style={{ fontSize: 10, color: "hsl(var(--muted-foreground))" }}>
                    {evt.event_type === "GATEWAY_CHANGE" || evt.event_type === "DNS_CHANGE" || evt.event_type === "INTERFACE_UP" || evt.event_type === "INTERFACE_DOWN"
                      ? evt.message || evt.event_type
                      : `${evt.protocol} ${evt.local_addr}:${evt.local_port} → ${evt.remote_addr}:${evt.remote_port}`}
                  </span>
                </div>
                <div style={{ fontSize: 10, color: "hsl(var(--muted-foreground))" }}>
                  {evt.process_name || "—"} {evt.pid ? `(PID ${evt.pid})` : ""}
                  {evt.address_family ? ` · ${evt.address_family}` : ""}
                  {evt.connection_id ? ` · ${evt.connection_id.slice(0, 14)}` : ""}
                  {evt.local_role ? ` · ${evt.local_role}→${evt.remote_role || "?"}` : ""}
                  {evt.previous_state && evt.state ? ` · ${evt.previous_state} → ${evt.state}` : ""}
                </div>
              </div>
              <div className="event-time">{fmtWhen(evt.timestamp)}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
