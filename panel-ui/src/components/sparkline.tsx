export function Sparkline({
  data,
  width = 560,
  height = 120,
  stroke = "oklch(0.696 0.17 162.48)",
}: {
  data: number[]
  width?: number
  height?: number
  stroke?: string
}) {
  if (!data.length) return null
  const max = Math.max(...data, 1)
  const pad = 6
  const stepX = (width - pad * 2) / Math.max(1, data.length - 1)
  const points = data.map((v, i) => {
    const x = pad + i * stepX
    const y = height - pad - (v / max) * (height - pad * 2)
    return `${x.toFixed(1)},${y.toFixed(1)}`
  })
  const area = `${pad},${height - pad} ${points.join(" ")} ${width - pad},${height - pad}`
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full" role="img" aria-label="traffic chart">
      <polygon points={area} fill={stroke} opacity={0.08} />
      <polyline points={points.join(" ")} fill="none" stroke={stroke} strokeWidth={2} strokeLinejoin="round" />
      {points.length > 0 && (
        <circle
          cx={points[points.length - 1].split(",")[0]}
          cy={points[points.length - 1].split(",")[1]}
          r={3}
          fill={stroke}
        />
      )}
    </svg>
  )
}
