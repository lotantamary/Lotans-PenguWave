import { useState, useEffect } from "react";
import { SecurityEvent } from "../types";
import { sanitizeHtml, toCsv } from "../utils";
import { getEvents } from "../api";

function severityColor(s: string): string {
  if (s === "CRITICAL") return "#8b0000";
  if (s === "HIGH") return "red";
  if (s === "MEDIUM") return "orange";
  if (s === "LOW") return "green";
  return "#666";
}

function formatDate(ts: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

export default function EventsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  useEffect(() => {
    getEvents()
      .then(setEvents)
      .catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load events"))
      .finally(() => setLoading(false));
  }, []);

  const filtered = events.filter((e) => {
    const matchesSearch =
      e.title.toLowerCase().includes(search.toLowerCase()) ||
      e.description.toLowerCase().includes(search.toLowerCase()) ||
      e.assetHostname.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severityFilter === "ALL" || e.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const handleExport = () => {
    const csv = toCsv(
      filtered.map((e) => ({
        id: e.id,
        timestamp: e.timestamp ?? "",
        severity: e.severity,
        title: e.title,
        assetHostname: e.assetHostname,
        assetIp: e.assetIp ?? "",
        sourceIp: e.sourceIp ?? "",
        tags: e.tags.join(";"),
        threatFlags: e.threatFlags.join(";"),
      }))
    );
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "penguwave_events_export.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) return <div className="page-container"><p>Loading events…</p></div>;
  if (error) return <div className="page-container"><p style={{ color: "red" }}>{error}</p></div>;

  return (
    <div className="page-container">
      <h1>Security Events</h1>

      <div style={{ marginBottom: 16, display: "flex", gap: 12, alignItems: "center" }}>
        <input
          type="text"
          placeholder="Search events..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ width: "100%", maxWidth: 400 }}
        />
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          style={{ width: 160 }}
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
      </div>

      {search && (
        <p style={{ marginBottom: 8 }}>
          Showing results for: <strong>{search}</strong> ({filtered.length} events)
        </p>
      )}

      {filtered.length === 0 ? (
        <p style={{ color: "#999" }}>No events found.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Title</th>
              <th>Threat</th>
              <th>Asset</th>
              <th>Source IP</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((event) => (
              <tr
                key={event.id}
                onClick={() => setSelectedEvent(event)}
                style={{ cursor: "pointer" }}
              >
                <td style={{ color: severityColor(event.severity), fontWeight: 600 }}>
                  {event.severity}
                </td>
                <td>{event.title}</td>
                <td>
                  {event.threatFlags.length > 0 && (
                    <span style={{ color: "#8b0000", fontWeight: 600 }}>
                      ⚠ {event.threatFlags.join(", ")}
                    </span>
                  )}
                </td>
                <td style={{ fontFamily: "monospace", fontSize: 13 }}>
                  {event.assetHostname}
                </td>
                <td style={{ fontFamily: "monospace", fontSize: 13 }}>
                  {event.sourceIp ?? "—"}
                </td>
                <td style={{ fontSize: 13 }}>{formatDate(event.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div style={{ marginTop: 12 }}>
        <button onClick={handleExport} style={{ fontSize: 13 }}>
          Export CSV
        </button>
      </div>

      {selectedEvent && (
        <div className="event-detail">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h2>{selectedEvent.title}</h2>
            <button onClick={() => setSelectedEvent(null)} style={{ cursor: "pointer" }}>
              Close
            </button>
          </div>
          <p>
            <strong>Severity:</strong>{" "}
            <span style={{ color: severityColor(selectedEvent.severity) }}>
              {selectedEvent.severity}
            </span>
          </p>
          {selectedEvent.threatFlags.length > 0 && (
            <p style={{ color: "#8b0000", fontWeight: 600, background: "#fff3f3", padding: "8px 12px", border: "1px solid #ffcccc", marginBottom: 8 }}>
              ⚠ Contains embedded attack payloads (rendered safely)
            </p>
          )}
          <p><strong>Description:</strong></p>
          <div
            dangerouslySetInnerHTML={{ __html: sanitizeHtml(selectedEvent.description) }}
            style={{ marginBottom: 8, lineHeight: 1.5 }}
          />
          <p>
            <strong>Asset:</strong> {selectedEvent.assetHostname}{" "}
            ({selectedEvent.assetIp ?? "—"})
          </p>
          <p>
            <strong>Source IP:</strong> {selectedEvent.sourceIp ?? "—"}
          </p>
          <p>
            <strong>Tags:</strong> {selectedEvent.tags.join(", ")}
          </p>
          <p>
            <strong>Timestamp:</strong> {formatDate(selectedEvent.timestamp)}
          </p>
        </div>
      )}
    </div>
  );
}
