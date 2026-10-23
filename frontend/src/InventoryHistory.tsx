import { date, rows } from "./api";
import type { Json } from "./api";

export function InventoryHistory({ entries }: { entries: Json[] }) {
  const history = rows(entries);
  if (!history.length)
    return (
      <p className="muted">
        No inventory history recorded yet. Enroll a node and collect an
        inventory.
      </p>
    );
  return (
    <div aria-label="Inventory change history">
      <p className="muted">
        Changes compare consecutive complete observations. A collection gap does
        not prove removal. The controller retains the latest 1,000 samples per
        host.
      </p>
      {history.map((entry) => (
        <section className="panel" key={entry.id}>
          <h3>Received {date(entry.received_at)}</h3>
          <p className="muted">
            Node observation: {date(entry.observed_at)} · Collection errors:{" "}
            {entry.collection_errors || 0}
          </p>
          {!Object.keys(entry.diff?.sections || {}).length && (
            <p>No structural baseline available for this sample.</p>
          )}
          {Object.entries(entry.diff?.sections || {}).map(([section, raw]) => {
            const change = raw as Json;
            const counts = change.counts || {};
            return (
              <div key={section} className="detail-meta">
                <strong>{section.replaceAll("_", " ")}</strong>
                {change.status === "unavailable" ? (
                  <span className="muted">
                    Unavailable — removals not inferred
                  </span>
                ) : (
                  <div>
                    <span>
                      {change.status === "first_observation"
                        ? "First observation"
                        : "Compared"}
                      : {counts.added || 0} added, {counts.changed || 0}{" "}
                      changed, {counts.removed || 0} removed
                    </span>
                    {["added", "changed", "removed"].map((kind) =>
                      change[kind]?.length ? (
                        <p key={kind} className="mono">
                          {kind}: {change[kind].join(", ")}
                        </p>
                      ) : null,
                    )}
                    {change.truncated && (
                      <p className="muted">
                        Identifiers limited to 100 per change type; counts
                        include all observations.
                      </p>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </section>
      ))}
    </div>
  );
}
