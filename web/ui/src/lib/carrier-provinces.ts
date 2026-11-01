// Province-level catalogue: https://www.zstaticcdn.com/ (TCP port 80).
export const carrierProvinceCodes = ['bj', 'tj', 'he', 'sx', 'nm', 'ln', 'jl', 'hl', 'sh', 'js', 'zj', 'ah', 'fj', 'jx', 'sd', 'ha', 'hb', 'hn', 'gd', 'gx', 'hi', 'cq', 'sc', 'gz', 'yn', 'xz', 'sn', 'gs', 'qh', 'nx', 'xj'] as const

export function defaultCarrierTargetText(protocol: string, family: string, province = 'bj'): string {
  if (!['tcp', 'icmp'].includes(protocol) || !['ipv4', 'ipv6'].includes(family)) return ''
  const code = province || 'bj'
  if (!carrierProvinceCodes.some(value => value === code)) return ''
  return [['CT', '4134'], ['CU', '4837'], ['CM', '9808']].map(([name, asn]) => {
    const address = protocol === 'tcp'
      ? `${code}-${name.toLowerCase()}-v${family === 'ipv4' ? '4' : '6'}.ip.zstaticcdn.com:80`
      : `${family}.pek-${asn}.endpoint.nxtrace.org`
    return `${name} ${address}`
  }).join('\n')
}
