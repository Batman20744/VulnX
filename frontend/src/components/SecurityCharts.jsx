
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  FunnelChart,
  Funnel,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  LabelList,
} from "recharts";

import ChartCard from "./ChartCard";

const GREEN = {
  deep: "#176B60",
  dark: "#218675",
  primary: "#2A9D8F",
  light: "#74C7B8",
  bright: "#A0E8D5",
};

const PALETTE = [
  GREEN.deep,
  GREEN.dark,
  GREEN.primary,
  GREEN.light,
];

const tooltipStyle = {
  backgroundColor: "#111B19",
  border: "1px solid #1F332F",
  borderRadius: "8px",
  color: "#E6EEEA",
  fontSize: "11px",
};

const axisStyle = {
  fill: "#A7B5AF",
  fontSize: 10,
};

function shortDate(value) {
  if (!value) return "Unknown";

  return new Date(value).toLocaleDateString("en", {
    month: "short",
    day: "numeric",
  });
}

function SecurityCharts({ assets = [], findings = [], scans = [] }) {
  // 1. Scan activity trend
  const trendData = [...scans]
    .filter((scan) => scan.started_at)
    .sort(
      (a, b) =>
        new Date(a.started_at) - new Date(b.started_at)
    )
    .map((scan) => ({
      date: shortDate(scan.started_at),
      findings: scan.total_findings ?? 0,
      scans: 1,
    }));

  // 2. Unique CVEs by severity for the impact funnel
  const cveSeverity = new Map();

  findings.forEach((finding) => {
    const id = finding.cve_id;

    if (!id) return;

    const current = cveSeverity.get(id);

    if (
      !current ||
      (finding.cvss_score ?? 0) > (current.cvss_score ?? 0)
    ) {
      cveSeverity.set(id, finding);
    }
  });

  const severityOrder = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
  ];

  const funnelData = severityOrder.map((severity) => ({
    name: severity,
    value: [...cveSeverity.values()].filter(
      (finding) => finding.severity?.toUpperCase() === severity
    ).length,
  })).filter((item) => item.value > 0);

  // 3. Finding age based on detection dates
  const now = Date.now();

  const ageRanges = [
    { name: "0–30", min: 0, max: 30 },
    { name: "31–60", min: 31, max: 60 },
    { name: "61–90", min: 61, max: 90 },
    { name: "91–180", min: 91, max: 180 },
    { name: "180+", min: 181, max: Infinity },
  ];

  const ageData = ageRanges.map((range) => ({
    age: range.name,
    count: findings.filter((finding) => {
      if (!finding.detected_at) return false;

      const ageDays = Math.max(
        0,
        Math.floor(
          (now - new Date(finding.detected_at).getTime()) /
            86400000
        )
      );

      return ageDays >= range.min && ageDays <= range.max;
    }).length,
  }));

  // 4. Operating system impact
  const assetMap = new Map(
    assets.map((asset) => [asset.id, asset])
  );

  const osCounts = new Map();

  findings.forEach((finding) => {
    const asset = assetMap.get(finding.asset_id);
    const os = asset?.operating_system || "Unknown";

    osCounts.set(os, (osCounts.get(os) || 0) + 1);
  });

  const osData = [...osCounts.entries()]
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);

  // 5. Product impact
  const productCounts = new Map();

  findings.forEach((finding) => {
    const asset = assetMap.get(finding.asset_id);
    const product = asset?.software_name || "Unknown";

    productCounts.set(
      product,
      (productCounts.get(product) || 0) + 1
    );
  });

  const productData = [...productCounts.entries()]
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 6);

  const hasTrend = trendData.length > 0;

  return (
    <div className="security-charts">

      {/* Vulnerability trend */}
      <ChartCard
        title="Vulnerabilities over time"
        subtitle="Findings recorded across completed and historical scans"
        className="trend-panel"
      >
        {hasTrend ? (
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={trendData}>
              <defs>
                <linearGradient
                  id="findingGradient"
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="1"
                >
                  <stop
                    offset="0%"
                    stopColor="#2A9D8F"
                    stopOpacity={0.4}
                  />
                  <stop
                    offset="95%"
                    stopColor="#2A9D8F"
                    stopOpacity={0.01}
                  />
                </linearGradient>
              </defs>

              <CartesianGrid
                stroke="#1F332F"
                strokeDasharray="3 4"
                vertical={false}
              />

              <XAxis
                dataKey="date"
                tick={axisStyle}
                axisLine={{ stroke: "#1F332F" }}
                tickLine={false}
              />

              <YAxis
                allowDecimals={false}
                tick={axisStyle}
                axisLine={false}
                tickLine={false}
              />

              <Tooltip
                contentStyle={tooltipStyle}
                cursor={false}
              />

              <Area
                type="monotone"
                dataKey="findings"
                name="Findings per scan"
                stroke="#2A9D8F"
                strokeWidth={3}
                fill="url(#findingGradient)"
                activeDot={{
                  r: 6,
                  fill: "#74C7B8",
                  stroke: "#0A0F0E",
                  strokeWidth: 2,
                }}
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="empty-state">
            No scan history available.
          </div>
        )}
      </ChartCard>

      {/* Three chart columns */}
      <div className="security-chart-row">

        {/* Active CVE funnel */}
        <ChartCard
          title="Impact funnel - Active CVEs"
          subtitle="Unique CVEs grouped by severity"
          className="funnel-panel"
        >
          {funnelData.length > 0 ? (
            <ResponsiveContainer width="100%" height={230}>
              <FunnelChart>
                <Tooltip
                  contentStyle={tooltipStyle}
                  cursor={false}
                />

                <Funnel
                  dataKey="value"
                  data={funnelData}
                  isAnimationActive
                >
                  {funnelData.map((item, index) => (
                    <Cell
                      key={item.name}
                      fill={PALETTE[index % PALETTE.length]}
                    />
                  ))}

                  <LabelList
                    position="right"
                    fill="#E6EEEA"
                    stroke="none"
                    dataKey="name"
                    fontSize={10}
                  />
                </Funnel>
              </FunnelChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state">
              No CVE records available.
            </div>
          )}
        </ChartCard>

        {/* Vulnerability age */}
        <ChartCard
          title="Vulnerabilities by age"
          subtitle="Age calculated from detection date"
          className="age-panel"
        >
          <ResponsiveContainer width="100%" height={230}>
            <BarChart data={ageData}>
              <defs>
                <linearGradient
                  id="ageGradient"
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="1"
                >
                  <stop
                    offset="0%"
                    stopColor="#74C7B8"
                  />
                  <stop
                    offset="100%"
                    stopColor="#176B60"
                  />
                </linearGradient>
              </defs>

              <CartesianGrid
                stroke="#1F332F"
                strokeDasharray="3 4"
                vertical={false}
              />

              <XAxis
                dataKey="age"
                tick={axisStyle}
                axisLine={false}
                tickLine={false}
              />

              <YAxis
                allowDecimals={false}
                tick={axisStyle}
                axisLine={false}
                tickLine={false}
              />

              <Tooltip
                contentStyle={tooltipStyle}
                cursor={false}
              />

              <Bar
                dataKey="count"
                name="Findings"
                fill="url(#ageGradient)"
                radius={[4, 4, 0, 0]}
                maxBarSize={42}
              />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* OS impact */}
        <ChartCard
          title="Impact by OS"
          subtitle="Findings grouped by asset operating system"
          className="os-panel"
        >
          {osData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={170}>
                <PieChart>
                  <Pie
                    data={osData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={70}
                    paddingAngle={3}
                  >
                    {osData.map((item, index) => (
                      <Cell
                        key={item.name}
                        fill={PALETTE[index % PALETTE.length]}
                      />
                    ))}
                  </Pie>

                  <Tooltip
                    contentStyle={tooltipStyle}
                    cursor={false}
                  />
                </PieChart>
              </ResponsiveContainer>

              <div className="compact-legend">
                {osData.map((item, index) => (
                  <div key={item.name}>
                    <span
                      className="legend-dot"
                      style={{
                        background: PALETTE[index % PALETTE.length],
                      }}
                    />
                    <span>{item.name}</span>
                    <strong>{item.value}</strong>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="empty-state">
              No OS impact data available.
            </div>
          )}
        </ChartCard>
      </div>

      {/* Product impact */}
      <ChartCard
        title="Impact by product"
        subtitle="Products ranked by recorded findings"
        className="product-panel"
      >
        {productData.length > 0 ? (
          <ResponsiveContainer width="100%" height={230}>
            <BarChart
              data={productData}
              layout="vertical"
              margin={{ left: 15, right: 25 }}
            >
              <defs>
                <linearGradient
                  id="productGradient"
                  x1="0"
                  y1="0"
                  x2="1"
                  y2="0"
                >
                  <stop
                    offset="0%"
                    stopColor="#176B60"
                  />
                  <stop
                    offset="100%"
                    stopColor="#74C7B8"
                  />
                </linearGradient>
              </defs>

              <CartesianGrid
                stroke="#1F332F"
                strokeDasharray="3 4"
                horizontal={false}
              />

              <XAxis
                type="number"
                allowDecimals={false}
                tick={axisStyle}
                axisLine={false}
                tickLine={false}
              />

              <YAxis
                type="category"
                dataKey="name"
                tick={axisStyle}
                width={75}
                axisLine={false}
                tickLine={false}
              />

              <Tooltip
                contentStyle={tooltipStyle}
                cursor={false}
              />

              <Bar
                dataKey="value"
                name="Findings"
                fill="url(#productGradient)"
                radius={[0, 5, 5, 0]}
                maxBarSize={22}
              />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="empty-state">
            No product impact data available.
          </div>
        )}
      </ChartCard>

      {/* Final vulnerability trend */}
      <ChartCard
        title="Vulnerability trends"
        subtitle="Finding counts across recorded scans"
        className="secondary-trend-panel"
      >
        {hasTrend ? (
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={trendData}>
              <CartesianGrid
                stroke="#1F332F"
                strokeDasharray="3 4"
              />

              <XAxis
                dataKey="date"
                tick={axisStyle}
                axisLine={false}
                tickLine={false}
              />

              <YAxis
                allowDecimals={false}
                tick={axisStyle}
                axisLine={false}
                tickLine={false}
              />

              <Tooltip
                contentStyle={tooltipStyle}
                cursor={false}
              />

              <Line
                type="monotone"
                dataKey="findings"
                name="Findings"
                stroke="#74C7B8"
                strokeWidth={3}
                dot={{
                  fill: "#74C7B8",
                  stroke: "#0A0F0E",
                  strokeWidth: 2,
                  r: 4,
                }}
                activeDot={{ r: 7 }}
              />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <div className="empty-state">
            No trend data available.
          </div>
        )}
      </ChartCard>
    </div>
  );
}

export default SecurityCharts;
