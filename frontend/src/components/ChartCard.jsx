
import { MoreHorizontal, Maximize2 } from "lucide-react";

function ChartCard({
  title,
  subtitle,
  children,
  className = "",
  action,
}) {
  return (
    <section className={`chart-card ${className}`}>
      <div className="chart-card-header">
        <div>
          <h3>{title}</h3>
          {subtitle && <p>{subtitle}</p>}
        </div>

        <div className="chart-card-actions">
          {action}

          <button
            className="chart-action-button"
            type="button"
            aria-label="More chart options"
          >
            <MoreHorizontal size={20} />
          </button>

          <button
            className="chart-action-button"
            type="button"
            aria-label="Expand chart"
          >
            <Maximize2 size={16} />
          </button>
        </div>
      </div>

      <div className="chart-card-content">
        {children}
      </div>
    </section>
  );
}

export default ChartCard;
