
function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  variant = "default",
}) {
  return (
    <article className={`stat-card ${variant}`}>
      <div className="stat-card-top">
        <span className="stat-title">{title}</span>

        {Icon && (
          <div className="stat-icon">
            <Icon size={20} strokeWidth={1.8} />
          </div>
        )}
      </div>

      <div className="stat-value">{value ?? "--"}</div>

      <div className="stat-card-bottom">
        <span className="stat-subtitle">{subtitle}</span>

        {trend && (
          <span className="stat-trend">
            {trend}
          </span>
        )}
      </div>
    </article>
  );
}

export default StatCard;
