export function formatRiskIndex(score) {
  return Number.isFinite(score) && score >= 0 && score <= 100
    ? `Risk index ${score}/100`
    : 'Score unavailable';
}
