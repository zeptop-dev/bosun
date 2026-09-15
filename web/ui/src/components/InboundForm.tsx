import { ActionIcon, Button, Card, Collapse, Group, JsonInput, NumberInput, Select, SimpleGrid, Stack, Switch, Text, TextInput, Tooltip, UnstyledButton } from '@mantine/core'
import { useForm } from '@mantine/form'
import { IconRefresh } from '@tabler/icons-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, type Fallback, type FallbackLimit, type Inbound, type Ingress, type IngressInput, type Settings } from '../lib/api'
import { useQuery } from '@tanstack/react-query'
import { IconPlus, IconTrash } from '@tabler/icons-react'
import { RealityScan, type RealityResult } from './RealityScan'
import { toast } from '../lib/notify'
import { IngressFields, clientHost, emptyIngress, ingressPayload, type IngressValues } from './IngressFields'

const protocols = ['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'anytls', 'mieru', 'snell', 'socks', 'http', 'naive', 'wireguard']
const cores = ['', 'singbox', 'xray', 'mita', 'hysteria', 'snell']
const transports = ['tcp', 'ws', 'grpc', 'httpupgrade', 'http', 'xhttp']
const ciphers = ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305', 'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'none']

// Values is the flat form model; toInbound folds it back into spec.Inbound JSON.
export type Values = {
  tag: string; remark: string; protocol: string; listen: string; port: number; core: string; enabled: boolean
  display_host: string; display_port: number; ingress_id: string
  tls: 'none' | 'tls' | 'reality'; auto_cert: boolean; acme: string; server_name: string; reality_private: string; reality_public: string; reality_short: string; handshake_server: string; handshake_port: number; fallback_off: boolean; fallback_after_mb: number; fallback_kbps: number
  transport: string; path: string; host: string; service_name: string; xhttp_mode: string
  flow: string; cipher: string; server_key: string; obfs: string; obfs_password: string; up_mbps: number; down_mbps: number
  congestion_control: string; mieru_transport: string; traffic_pattern: string; mieru_mtu: number | string; mieru_multiplexing: string; mieru_handshake: string
  snell_psk: string; snell_version: number; snell_obfs: string; snell_obfs_host: string
  wg_private: string; wg_public: string; wg_address: string; wg_mtu: number
  fallbacks: Fallback[]
  extra: string
}

export const empty: Values = {
  tag: '', remark: '', protocol: 'vless', listen: '', port: 443, core: '', enabled: true, display_host: '', display_port: 0, ingress_id: '',
  tls: 'none', auto_cert: false, acme: 'http', server_name: '', reality_private: '', reality_public: '', reality_short: '', handshake_server: '', handshake_port: 443, fallback_off: false, fallback_after_mb: 1, fallback_kbps: 64,
  transport: 'tcp', path: '', host: '', service_name: '', xhttp_mode: '',
  flow: '', cipher: '2022-blake3-aes-128-gcm', server_key: '', obfs: '', obfs_password: '', up_mbps: 0, down_mbps: 0,
  congestion_control: 'bbr', mieru_transport: 'TCP', traffic_pattern: '', mieru_mtu: '', mieru_multiplexing: '', mieru_handshake: '',
  snell_psk: '', snell_version: 5, snell_obfs: '', snell_obfs_host: '', wg_private: '', wg_public: '', wg_address: '10.66.0.1/16', wg_mtu: 1420, fallbacks: [], extra: '{}',
}

const known = new Set(['tag', 'remark', 'protocol', 'listen', 'port', 'core', 'enabled', 'display_host', 'display_port', 'ingress_id', 'tls', 'transport', 'flow', 'cipher', 'server_key', 'obfs', 'obfs_password', 'up_mbps', 'down_mbps', 'congestion_control', 'mieru_transport', 'traffic_pattern', 'assigned_core', 'scoped_users', 'users', 'mieru_mtu', 'mieru_multiplexing', 'mieru_handshake', 'snell_psk', 'snell_version', 'snell_obfs', 'snell_obfs_host', 'fallbacks', 'wg_private_key', 'wg_public_key', 'wg_address', 'wg_mtu'])

export function toValues(ib?: Inbound): Values {
  if (!ib) return empty
  const extra: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(ib)) if (!known.has(k)) extra[k] = v
  const tlsMode = ib.tls?.mode === 2 ? 'reality' : ib.tls?.mode === 1 ? 'tls' : 'none'
  return {
    ...empty,
    tag: ib.tag, remark: ib.remark ?? '', protocol: ib.protocol, listen: ib.listen ?? '', port: ib.port, core: ib.core ?? '', enabled: ib.enabled,
    display_host: ib.display_host ?? '', display_port: ib.display_port ?? 0, ingress_id: ib.ingress_id ?? '',
    tls: tlsMode, auto_cert: ib.tls?.auto_cert ?? false, acme: ib.tls?.acme || 'http', server_name: ib.tls?.server_name ?? '', reality_private: ib.tls?.reality?.private_key ?? '', reality_public: ib.tls?.reality?.public_key ?? '',
    reality_short: ib.tls?.reality?.short_ids?.[0] ?? '', handshake_server: ib.tls?.reality?.handshake_server ?? '', handshake_port: ib.tls?.reality?.handshake_port ?? 443,
    fallback_off: ib.tls?.reality?.fallback_limit?.off ?? false, fallback_after_mb: Math.round((ib.tls?.reality?.fallback_limit?.after_bytes || 1048576) / 1048576), fallback_kbps: Math.round((ib.tls?.reality?.fallback_limit?.bytes_per_sec || 65536) / 1024),
    transport: ib.transport?.type ?? 'tcp', path: ib.transport?.path ?? '', host: ib.transport?.host ?? '', service_name: ib.transport?.service_name ?? '', xhttp_mode: ib.transport?.mode ?? '',
    flow: ib.flow ?? '', cipher: ib.cipher ?? empty.cipher, server_key: ib.server_key ?? '', obfs: ib.obfs ?? '', obfs_password: ib.obfs_password ?? '',
    up_mbps: ib.up_mbps ?? 0, down_mbps: ib.down_mbps ?? 0, congestion_control: ib.congestion_control ?? 'bbr', mieru_transport: ib.mieru_transport ?? 'TCP', traffic_pattern: ib.traffic_pattern ?? '', mieru_mtu: ib.mieru_mtu || '', mieru_multiplexing: ib.mieru_multiplexing ?? '', mieru_handshake: ib.mieru_handshake ?? '',
    snell_psk: ib.snell_psk ?? '', snell_version: ib.snell_version || 5, snell_obfs: ib.snell_obfs ?? '', snell_obfs_host: ib.snell_obfs_host ?? '',
    wg_private: ib.wg_private_key ?? '', wg_public: ib.wg_public_key ?? '', wg_address: ib.wg_address || '10.66.0.1/16', wg_mtu: ib.wg_mtu || 1420,
    fallbacks: (ib.fallbacks ?? []).map((f) => ({ name: f.name ?? '', alpn: f.alpn ?? '', path: f.path ?? '', dest: f.dest, xver: f.xver ?? 0 })),
    extra: JSON.stringify(extra, null, 2),
  }
}

function fallbackLimit(v: Values): FallbackLimit | undefined {
  if (v.fallback_off) return { off: true }
  const after = Math.max(0, Number(v.fallback_after_mb) || 0) * 1048576, rate = Math.max(0, Number(v.fallback_kbps) || 0) * 1024
  if ((after === 1048576 || after === 0) && (rate === 65536 || rate === 0)) return undefined
  return { after_bytes: after || undefined, bytes_per_sec: rate || undefined }
}

export function toInbound(v: Values): Record<string, unknown> {
  const out: Record<string, unknown> = { ...JSON.parse(v.extra || '{}'), tag: v.tag, remark: v.remark, protocol: v.protocol, listen: v.listen, port: v.port, core: v.core, enabled: v.enabled, display_host: v.display_host, display_port: v.display_port, ingress_id: v.ingress_id }
  const stream = ['vless', 'vmess', 'trojan', 'shadowsocks', 'anytls', 'socks', 'http'].includes(v.protocol)
  const quic = ['hysteria2', 'tuic', 'naive'].includes(v.protocol)
  if (v.tls === 'tls' && ['vless', 'trojan'].includes(v.protocol) && v.transport === 'tcp' && v.fallbacks.length) out.fallbacks = v.fallbacks.filter((f) => f.dest.trim()).map((f) => ({ name: f.name || undefined, alpn: f.alpn || undefined, path: f.path || undefined, dest: f.dest.trim(), xver: f.xver || undefined }))
  if (v.tls === 'reality') out.tls = { mode: 2, server_name: v.server_name, reality: { private_key: v.reality_private, public_key: v.reality_public, short_ids: v.reality_short ? [v.reality_short] : [], handshake_server: v.handshake_server || v.server_name, handshake_port: v.handshake_port || 443, fallback_limit: fallbackLimit(v) } }
  else if (v.tls === 'tls' || quic) out.tls = { mode: 1, server_name: v.server_name, auto_cert: v.auto_cert, acme: v.auto_cert ? v.acme : '' }
  if (stream && v.transport !== 'tcp') out.transport = { type: v.transport, path: v.path, host: v.host, service_name: v.service_name, mode: v.xhttp_mode }
  if (v.protocol === 'vless' && v.flow) out.flow = v.flow
  if (v.protocol === 'shadowsocks') { out.cipher = v.cipher; if (v.cipher.startsWith('2022')) out.server_key = v.server_key }
  if (v.protocol === 'hysteria2') { if (v.obfs) { out.obfs = v.obfs; out.obfs_password = v.obfs_password } if (v.up_mbps) out.up_mbps = v.up_mbps; if (v.down_mbps) out.down_mbps = v.down_mbps }
  if (v.protocol === 'tuic') out.congestion_control = v.congestion_control
  if (v.protocol === 'mieru') {
    out.mieru_transport = v.mieru_transport
    if (v.traffic_pattern) out.traffic_pattern = v.traffic_pattern
    if (Number(v.mieru_mtu)) out.mieru_mtu = Number(v.mieru_mtu)
    if (v.mieru_multiplexing) out.mieru_multiplexing = v.mieru_multiplexing
    if (v.mieru_handshake) out.mieru_handshake = v.mieru_handshake
  }
  if (v.protocol === 'wireguard') { out.wg_private_key = v.wg_private; out.wg_public_key = v.wg_public; out.wg_address = v.wg_address; out.wg_mtu = Number(v.wg_mtu) || 1420 }
  if (v.protocol === 'naive') out.tls = { mode: 1, server_name: v.server_name, auto_cert: v.auto_cert, acme: v.auto_cert ? v.acme : '' }
  if (v.protocol === 'snell') {
    out.snell_psk = v.snell_psk
    out.snell_version = Number(v.snell_version) || 5
    if (v.snell_obfs) { out.snell_obfs = v.snell_obfs; out.snell_obfs_host = v.snell_obfs_host }
  }
  return out
}

// mieru strategies, the same presets as nobrand-oneclick and Captain: all
// TCP, the difference is mita's trafficPattern (off / conservative / aggressive).
const mieruPatterns: Record<string, unknown> = {
  iplc: undefined,
  balanced: { seed: 0, unlockAll: false, nonce: { type: 'NONCE_TYPE_PRINTABLE', applyToAllUDPPacket: true, minLen: 4, maxLen: 8 }, padding: { maxMiddlePaddingLen: 0, maxEndPaddingLen: 128 } },
  stealth: { seed: 0, unlockAll: false, tcpFragment: { enable: true, maxSleepMs: 8 }, nonce: { type: 'NONCE_TYPE_PRINTABLE', applyToAllUDPPacket: true, minLen: 6, maxLen: 12 }, padding: { maxMiddlePaddingLen: 64, maxEndPaddingLen: 255 } },
}
function mieruStrategyOf(pattern: string): string {
  if (!pattern.trim()) return 'iplc'
  try {
    const tp = JSON.parse(pattern)
    for (const k of ['balanced', 'stealth']) if (JSON.stringify(tp) === JSON.stringify(mieruPatterns[k])) return k
  } catch { /* free-form */ }
  return 'custom'
}
function mieruPatternFor(strategy: string, current: string): string {
  // Custom starts from the current preset (or the conservative one) with
  // every field spelled out, so the operator edits rather than recalls.
  if (strategy === 'custom') {
    if (current.trim()) { try { return JSON.stringify(JSON.parse(current), null, 2) } catch { return current } }
    return JSON.stringify({ ...(mieruPatterns.balanced as object), tcpFragment: { enable: false, maxSleepMs: 0 }, lowEntropy: { mode: 'LOW_ENTROPY_MODE_OFF', maskRotation: 'LOW_ENTROPY_MASK_NO_ROTATION' } }, null, 2)
  }
  const tp = mieruPatterns[strategy]
  return tp ? JSON.stringify(tp) : ''
}

const recipes: { key: string; values: Partial<Values> }[] = [
  { key: 'vlessReality', values: { protocol: 'vless', port: 443, tls: 'reality', server_name: 'www.apple.com', handshake_server: 'www.apple.com', flow: 'xtls-rprx-vision', transport: 'tcp' } },
  { key: 'hysteria2', values: { protocol: 'hysteria2', port: 8443, tls: 'tls', auto_cert: true, obfs: 'salamander', up_mbps: 100, down_mbps: 500 } },
  { key: 'mieru', values: { protocol: 'mieru', port: 24450, tls: 'none', mieru_transport: 'TCP' } },
  // The IPLC recipe also picks (or describes) a line ingress; see apply().
  { key: 'ss2022', values: { protocol: 'shadowsocks', port: 8388, tls: 'none', cipher: '2022-blake3-aes-128-gcm' } },
  { key: 'trojanWs', values: { protocol: 'trojan', port: 443, tls: 'tls', auto_cert: true, transport: 'ws', path: '/trojan' } },
  { key: 'anytls', values: { protocol: 'anytls', port: 8444, tls: 'tls', auto_cert: true } },
  { key: 'snell5', values: { protocol: 'snell', port: 6160, tls: 'none', snell_version: 5, snell_obfs: '' } },
  { key: 'wireguard', values: { protocol: 'wireguard', port: 51820, tls: 'none', wg_address: '10.66.0.1/16', wg_mtu: 1420 } },
]

export type InboundSubmit = { body: Record<string, unknown>; ingress?: IngressInput }

export function InboundForm({ initial, onSubmit, busy, onCancel, ingresses = [], usedPorts = [], lineOnly }: { initial: Values; onSubmit: (v: InboundSubmit) => void; busy: boolean; onCancel: () => void; ingresses?: Ingress[]; usedPorts?: number[]; lineOnly?: boolean }) {
  const { t } = useTranslation()
  const [advanced, setAdvanced] = useState(false)
  const [recipe, setRecipe] = useState<string | null>(null) // highlighted quick-setup card
  const form = useForm<Values>({
    initialValues: initial,
    validate: {
      tag: (v) => (v.trim() ? null : t('form.required')),
      port: (v) => (v > 0 && v < 65536 ? null : t('form.port')),
      extra: (v) => { try { JSON.parse(v || '{}'); return null } catch { return t('form.json') } },
      reality_private: (v, all) => (all.tls === 'reality' && !v ? t('form.required') : null),
      server_key: (v, all) => (all.protocol === 'shadowsocks' && all.cipher.startsWith('2022') && !v ? t('form.required') : null),
      snell_psk: (v, all) => (all.protocol === 'snell' && !v ? t('form.required') : null),
    },
  })
  // A new line ingress described inline; created before the inbound on save.
  const [newIngress, setNewIngress] = useState(false)
  // A node reachable only through a line (no public address set) defaults new inbounds to its first ingress.
  const ingressForm = useForm<IngressValues>({ initialValues: emptyIngress, validate: { Name: (v) => (v.trim() ? null : t('form.required')) } })
  const v = form.values
  const selectedIngress = ingresses.find((g) => g.id === v.ingress_id)
  const firstFree = (g?: { port_from: number; port_to: number; reserved_ports?: number[] }) => { if (!g || !g.port_from) return 0; for (let p = g.port_from; p <= g.port_to; p++) if (!usedPorts.includes(p) && !(g.reserved_ports ?? []).includes(p)) return p; return 0 }
  useEffect(() => { if (lineOnly && !initial.ingress_id && !initial.tag && ingresses[0]) form.setValues({ ingress_id: ingresses[0].id, port: firstFree(ingresses[0]) || form.values.port }) }, []) // eslint-disable-line react-hooks/exhaustive-deps
  const onIngress = (val: string | null) => {
    if (val === 'new') { setNewIngress(true); ingressForm.setValues(emptyIngress); form.setFieldValue('ingress_id', ''); return }
    setNewIngress(false)
    const g = ingresses.find((x) => x.id === val)
    form.setValues({ ingress_id: val ?? '', port: g && g.port_from ? firstFree(g) || v.port : v.port })
  }
  const stream = ['vless', 'vmess', 'trojan', 'shadowsocks', 'anytls', 'socks', 'http'].includes(v.protocol)
  const quic = ['hysteria2', 'tuic', 'naive'].includes(v.protocol)
  const tlsCapable = stream && v.protocol !== 'shadowsocks'
  const settingsQ = useQuery({ queryKey: ['settings'], queryFn: () => api.get<Settings>('/api/settings'), staleTime: 60_000 })
  const decoy = settingsQ.data?.decoy_enabled && settingsQ.data.decoy_domain ? settingsQ.data : null
  const canFallback = v.tls === 'tls' && ['vless', 'trojan'].includes(v.protocol) && v.transport === 'tcp'
  const genReality = async () => {
    try { const k = await api.post<{ private_key: string; public_key: string; short_id: string }>('/api/keys/reality'); form.setValues({ reality_private: k.private_key, reality_public: k.public_key, reality_short: v.reality_short || k.short_id }) } catch (e) { toast.err(e) }
  }
  const genKey = async () => {
    try { const k = await api.post<{ key: string }>(`/api/keys/ss2022?cipher=${encodeURIComponent(v.cipher)}`); form.setFieldValue('server_key', k.key) } catch (e) { toast.err(e) }
  }
  const genPassword = async () => {
    try { const k = await api.post<{ password: string }>('/api/keys/password'); form.setFieldValue('obfs_password', k.password) } catch (e) { toast.err(e) }
  }
  const genWG = async () => {
    try { const k = await api.post<{ private_key: string; public_key: string }>('/api/keys/wireguard'); form.setValues({ wg_private: k.private_key, wg_public: k.public_key }) } catch (e) { toast.err(e) }
  }
  const genPSK = async () => {
    try { const k = await api.post<{ password: string }>('/api/keys/password'); form.setFieldValue('snell_psk', k.password) } catch (e) { toast.err(e) }
  }
  const apply = (r: (typeof recipes)[number]) => {
    // A recipe keeps the chosen line ingress and takes a port from its range; any protocol may ride a line.
    const port = selectedIngress && selectedIngress.port_from ? (firstFree(selectedIngress) || r.values.port) : r.values.port
    form.setValues({ ...empty, ...r.values, port, tag: v.tag || r.values.protocol!, remark: v.remark, enabled: true, ingress_id: v.ingress_id })
    if (r.values.tls === 'reality') void genReality()
    if (r.values.cipher?.startsWith('2022')) void genKey()
    if (r.values.obfs) void genPassword()
    if (r.values.protocol === 'snell') void genPSK()
    if (r.values.protocol === 'wireguard') void genWG()
  }
  const submit = (vals: Values) => {
    if (newIngress) {
      if (ingressForm.validate().hasErrors) return
      onSubmit({ body: toInbound(vals), ingress: ingressPayload(ingressForm.values) })
      return
    }
    onSubmit({ body: toInbound(vals) })
  }
  const ingressLabel = (g: Ingress) => `${g.name} → ${clientHost(g) || t('ingress.noEntry')}`
  return (
    <form onSubmit={form.onSubmit(submit)}>
      <Stack>
        <div>
          <Text size="sm" fw={600}>{t('inbounds.recipe')}</Text>
          <Text size="xs" c="dimmed" mb="xs">{t('inbounds.recipeHint')}</Text>
          <SimpleGrid cols={{ base: 2, sm: 3 }} spacing="xs">
            {recipes.map((r) => (
              <UnstyledButton key={r.key} onClick={() => { setRecipe(r.key); apply(r) }} aria-pressed={recipe === r.key}>
                <Card p="sm" withBorder style={{ height: '100%', borderColor: recipe === r.key ? 'var(--mantine-primary-color-filled)' : undefined, background: recipe === r.key ? 'var(--mantine-primary-color-light)' : undefined }}>
                  <Text size="sm" fw={600} c={recipe === r.key ? 'var(--mantine-primary-color-light-color)' : undefined}>{t(`inbounds.recipes.${r.key}`)}</Text>
                  <Text size="xs" c="dimmed" lh={1.35} lineClamp={2} mih="2.7em">{t(`inbounds.recipes.${r.key}Desc`)}</Text>
                </Card>
              </UnstyledButton>
            ))}
          </SimpleGrid>
        </div>
        <Group grow>
          <TextInput label={t('inbounds.tag')} required {...form.getInputProps('tag')} />
          <TextInput label={t('inbounds.remark')} placeholder={t('inbounds.remarkHint')} {...form.getInputProps('remark')} />
          <Select label={t('inbounds.protocol')} data={protocols} required allowDeselect={false} {...form.getInputProps('protocol')} />
        </Group>
        <Select label={t('inbounds.ingress')}
          description={newIngress ? t('inbounds.ingressNewHint') : selectedIngress ? (t('inbounds.ingressHint', { host: clientHost(selectedIngress) || t('ingress.noEntry'), ports: selectedIngress.port_from ? `${selectedIngress.port_from}–${selectedIngress.port_to}` : t('ingress.anyPort') }) + (selectedIngress.bind_ip ? ' ' + t('inbounds.ingressBindHint', { ip: selectedIngress.bind_ip }) : '')) : t('inbounds.ingressDirectHint')}
          allowDeselect={false}
          data={[{ value: '', label: t('inbounds.ingressDirect') }, ...ingresses.map((g) => ({ value: g.id, label: ingressLabel(g) })), { value: 'new', label: t('inbounds.ingressNew') }]}
          value={newIngress ? 'new' : v.ingress_id} onChange={onIngress} />
        {lineOnly && !v.ingress_id && !newIngress && <Text size="xs" c="orange">{t('inbounds.lineOnlyHint')}</Text>}
        {newIngress && (
          <Stack gap="xs" p="sm" style={{ border: '1px dashed var(--mantine-color-default-border)', borderRadius: 8 }}>
            <Text size="xs" c="dimmed">{t('inbounds.ingressNewFields')}</Text>
            <IngressFields form={ingressForm} />
          </Stack>
        )}
        <Group grow>
          <TextInput label={t('inbounds.listen')} placeholder={selectedIngress?.bind_ip || '::'} {...form.getInputProps('listen')} />
          <NumberInput label={t('inbounds.port')} min={1} max={65535} required {...form.getInputProps('port')} />
          <Select label={t('inbounds.core')} data={cores.map((c) => ({ value: c, label: c || t('inbounds.coreAuto') }))} allowDeselect={false} {...form.getInputProps('core')} />
          <Switch mt={24} label={t('inbounds.enabled')} {...form.getInputProps('enabled', { type: 'checkbox' })} />
        </Group>

        {(tlsCapable || quic) && (
          <Card p="sm">
            <Group grow align="flex-start">
              {tlsCapable
                ? <Select label={t('inbounds.tls')} description={t('inbounds.tlsHint')} data={[{ value: 'none', label: t('inbounds.tlsNone') }, { value: 'tls', label: 'TLS' }, { value: 'reality', label: 'REALITY' }]} allowDeselect={false} {...form.getInputProps('tls')} />
                : <TextInput label={t('inbounds.tls')} description={t('inbounds.tlsHint')} value="TLS" disabled />}
              {(v.tls !== 'none' || quic) && <TextInput label={t('inbounds.serverName')} description={v.tls === 'reality' ? t('inbounds.serverNameReality') : v.auto_cert ? t('inbounds.serverNameAuto') : t('inbounds.serverNameTls')} {...form.getInputProps('server_name')} />}
            </Group>
            {(v.tls === 'tls' || quic) && (
              <Group mt="sm" align="flex-end">
                <Switch label={t('inbounds.autoCert')} description={t('inbounds.autoCertHint')} {...form.getInputProps('auto_cert', { type: 'checkbox' })} />
                {v.auto_cert && <Select label={t('inbounds.acme')} data={[{ value: 'http', label: t('inbounds.acmeHttp') }, { value: 'dns', label: t('inbounds.acmeDns') }]} allowDeselect={false} {...form.getInputProps('acme')} />}
              </Group>
            )}
            {canFallback && (
              <Stack gap={6} mt="sm">
                <Group justify="space-between"><div><Text size="sm" fw={600}>{t('inbounds.fallbacks')}</Text><Text size="xs" c="dimmed">{t('inbounds.fallbacksHint')}</Text></div>
                  <Button size="compact-xs" variant="light" leftSection={<IconPlus size={12} />} onClick={() => form.setFieldValue('fallbacks', [...v.fallbacks, { name: '', alpn: '', path: '', dest: v.fallbacks.length ? '' : '80', xver: 0 }])}>{t('inbounds.fallbackAdd')}</Button></Group>
                {v.fallbacks.map((f, i) => (
                  <Group key={i} gap="xs" align="flex-end" wrap="nowrap">
                    <TextInput size="xs" label={t('inbounds.fallbackDest')} placeholder="80 / 127.0.0.1:8080 / /run/site.sock" required style={{ flex: 2 }} value={f.dest} onChange={(e) => form.setFieldValue(`fallbacks.${i}.dest`, e.currentTarget.value)} />
                    <TextInput size="xs" label="SNI" placeholder="*" style={{ flex: 1 }} value={f.name} onChange={(e) => form.setFieldValue(`fallbacks.${i}.name`, e.currentTarget.value)} />
                    <TextInput size="xs" label="ALPN" placeholder="*" style={{ flex: 1 }} value={f.alpn} onChange={(e) => form.setFieldValue(`fallbacks.${i}.alpn`, e.currentTarget.value)} />
                    <TextInput size="xs" label={t('inbounds.path')} placeholder="*" style={{ flex: 1 }} value={f.path} onChange={(e) => form.setFieldValue(`fallbacks.${i}.path`, e.currentTarget.value)} />
                    <Select size="xs" label="PROXY" data={[{ value: '0', label: t('common.none') }, { value: '1', label: 'v1' }, { value: '2', label: 'v2' }]} allowDeselect={false} w={90} value={String(f.xver ?? 0)} onChange={(x) => form.setFieldValue(`fallbacks.${i}.xver`, Number(x ?? 0))} />
                    <ActionIcon variant="subtle" color="red" mb={2} onClick={() => form.setFieldValue('fallbacks', v.fallbacks.filter((_, j) => j !== i))}><IconTrash size={14} /></ActionIcon>
                  </Group>
                ))}
              </Stack>
            )}
            {v.tls === 'reality' && tlsCapable && (
              <Stack gap="xs" mt="sm">
                <Group align="flex-end" wrap="nowrap">
                  <TextInput label={t('inbounds.realityPrivate')} required style={{ flex: 1 }} {...form.getInputProps('reality_private')} />
                  <TextInput label={t('inbounds.realityPublic')} style={{ flex: 1 }} {...form.getInputProps('reality_public')} />
                  <Tooltip label={t('inbounds.generateKeypair')}><ActionIcon variant="light" size="input-sm" aria-label={t('inbounds.generateKeypair')} onClick={genReality}><IconRefresh size={16} /></ActionIcon></Tooltip>
                </Group>
                <Group grow>
                  <TextInput label={t('inbounds.shortId')} {...form.getInputProps('reality_short')} />
                  <TextInput label={t('inbounds.handshakeServer')} placeholder={v.server_name} {...form.getInputProps('handshake_server')} />
                  <NumberInput label={t('inbounds.handshakePort')} {...form.getInputProps('handshake_port')} />
                </Group>
                <RealityScan current={v.handshake_server || v.server_name} scan={(hosts) => api.post<RealityResult[]>('/api/reality/scan', { hosts })}
                  onPick={(host) => form.setValues({ server_name: host, handshake_server: host, handshake_port: 443 })} />
                {decoy && (
                  <Group gap="xs">
                    <Button size="xs" variant="light" color="teal" onClick={() => form.setValues({ server_name: decoy.decoy_domain, handshake_server: '127.0.0.1', handshake_port: 4443 })}>{t('inbounds.useDecoy', { domain: decoy.decoy_domain })}</Button>
                    <Text size="xs" c="dimmed">{t('inbounds.useDecoyHint')}</Text>
                  </Group>
                )}
                <div>
                  <Group grow align="flex-end">
                    <Switch label={t('inbounds.fallbackLimit')} mb={7} checked={!v.fallback_off} onChange={(e) => form.setFieldValue('fallback_off', !e.currentTarget.checked)} />
                    <NumberInput label={t('inbounds.fallbackAfter')} min={0} disabled={v.fallback_off} {...form.getInputProps('fallback_after_mb')} />
                    <NumberInput label={t('inbounds.fallbackRate')} min={1} disabled={v.fallback_off} {...form.getInputProps('fallback_kbps')} />
                  </Group>
                  <Text size="xs" c="dimmed" mt={4}>{t('inbounds.fallbackLimitHint')}</Text>
                </div>
              </Stack>
            )}
          </Card>
        )}

        {stream && (
          <Card p="sm">
            <Group grow>
              <Select label={t('inbounds.transport')} data={transports} allowDeselect={false} {...form.getInputProps('transport')} />
              {['ws', 'httpupgrade', 'http', 'xhttp'].includes(v.transport) && <TextInput label={t('inbounds.path')} placeholder="/" {...form.getInputProps('path')} />}
              {['ws', 'httpupgrade', 'http', 'xhttp'].includes(v.transport) && <TextInput label="Host" {...form.getInputProps('host')} />}
              {v.transport === 'grpc' && <TextInput label="serviceName" {...form.getInputProps('service_name')} />}
              {v.transport === 'xhttp' && <Select label="mode" data={['', 'auto', 'packet-up', 'stream-up', 'stream-one']} {...form.getInputProps('xhttp_mode')} />}
              {v.protocol === 'vless' && v.transport === 'tcp' && v.tls !== 'none' && <Select label="flow" data={['', 'xtls-rprx-vision']} {...form.getInputProps('flow')} />}
            </Group>
          </Card>
        )}

        {v.protocol === 'shadowsocks' && (
          <Group align="flex-end" wrap="nowrap">
            <Select label={t('inbounds.cipher')} data={ciphers} allowDeselect={false} style={{ flex: 1 }} {...form.getInputProps('cipher')} />
            {v.cipher.startsWith('2022') && <TextInput label={t('inbounds.serverKey')} required style={{ flex: 1 }} {...form.getInputProps('server_key')} />}
            {v.cipher.startsWith('2022') && <Tooltip label={t('inbounds.generateKey')}><ActionIcon variant="light" size="input-sm" aria-label={t('inbounds.generateKey')} onClick={genKey}><IconRefresh size={16} /></ActionIcon></Tooltip>}
          </Group>
        )}
        {v.protocol === 'hysteria2' && (
          <Group grow align="flex-end">
            <Select label={t('inbounds.obfs')} data={[{ value: '', label: t('common.none') }, { value: 'salamander', label: 'salamander' }]} {...form.getInputProps('obfs')} />
            {v.obfs && <TextInput label={t('inbounds.obfsPassword')} {...form.getInputProps('obfs_password')} />}
            <NumberInput label={t('inbounds.upMbps')} min={0} {...form.getInputProps('up_mbps')} />
            <NumberInput label={t('inbounds.downMbps')} min={0} {...form.getInputProps('down_mbps')} />
          </Group>
        )}
        {v.protocol === 'tuic' && <Select label={t('inbounds.congestion')} data={['bbr', 'cubic', 'new_reno']} allowDeselect={false} {...form.getInputProps('congestion_control')} />}
        {v.protocol === 'mieru' && (
          <Group grow align="flex-start">
            <Select label={t('inbounds.mieruStrategy')} description={t('inbounds.mieruStrategyHint')} allowDeselect={false}
              data={[{ value: 'iplc', label: t('inbounds.mieru.iplc') }, { value: 'balanced', label: t('inbounds.mieru.balanced') }, { value: 'stealth', label: t('inbounds.mieru.stealth') }, { value: 'custom', label: t('inbounds.mieru.custom') }]}
              value={mieruStrategyOf(v.traffic_pattern)} onChange={(k) => k && form.setFieldValue('traffic_pattern', mieruPatternFor(k, v.traffic_pattern))} />
            <Select label={t('inbounds.mieruTransport')} description={v.mieru_transport === 'BOTH' ? t('inbounds.mieruBothHint', { port: Number(v.port) + 1 }) : undefined} data={[{ value: 'TCP', label: 'TCP' }, { value: 'UDP', label: 'UDP' }, { value: 'BOTH', label: t('inbounds.mieruBoth') }]} allowDeselect={false} {...form.getInputProps('mieru_transport')} />
          </Group>
        )}
        {v.protocol === 'mieru' && (
          <Group grow align="flex-start">
            <NumberInput label={t('inbounds.mieruMtu')} description={t('inbounds.mieruMtuHint')} placeholder="1400" min={1280} max={1500} {...form.getInputProps('mieru_mtu')} />
            <Select label={t('inbounds.mieruMux')} description={t('inbounds.mieruMuxHint')} allowDeselect={false}
              data={[{ value: '', label: t('inbounds.clientDefault') }, { value: 'MULTIPLEXING_OFF', label: t('inbounds.muxOff') }, { value: 'MULTIPLEXING_LOW', label: t('inbounds.muxLow') }, { value: 'MULTIPLEXING_MIDDLE', label: t('inbounds.muxMiddle') }, { value: 'MULTIPLEXING_HIGH', label: t('inbounds.muxHigh') }]}
              {...form.getInputProps('mieru_multiplexing')} />
            <Select label={t('inbounds.mieruHandshake')} description={t('inbounds.mieruHandshakeHint')} allowDeselect={false}
              data={[{ value: '', label: t('inbounds.clientDefault') }, { value: 'HANDSHAKE_NO_WAIT', label: t('inbounds.handshakeNoWait') }, { value: 'HANDSHAKE_STANDARD', label: t('inbounds.handshakeStandard') }]}
              {...form.getInputProps('mieru_handshake')} />
          </Group>
        )}
        {v.protocol === 'wireguard' && (
          <Card p="sm">
            <Text size="xs" c="dimmed" mb="xs">{t('inbounds.wgHint')}</Text>
            <Group align="flex-end" wrap="nowrap">
              <TextInput label={t('inbounds.wgPrivate')} required style={{ flex: 1 }} {...form.getInputProps('wg_private')} />
              <TextInput label={t('inbounds.wgPublic')} style={{ flex: 1 }} {...form.getInputProps('wg_public')} />
              <Tooltip label={t('inbounds.generateKeypair')}><ActionIcon variant="light" size="input-sm" aria-label={t('inbounds.generateKeypair')} onClick={genWG}><IconRefresh size={16} /></ActionIcon></Tooltip>
            </Group>
            <Group grow align="flex-start" mt="xs">
              <TextInput label={t('inbounds.wgAddress')} description={t('inbounds.wgAddressHint')} {...form.getInputProps('wg_address')} />
              <NumberInput label="MTU" min={1280} max={1500} {...form.getInputProps('wg_mtu')} />
            </Group>
          </Card>
        )}
        {v.protocol === 'snell' && (
          <Card p="sm">
            <Text size="xs" c="dimmed" mb="xs">{t('inbounds.snellHint')}</Text>
            <Group align="flex-end" wrap="nowrap">
              <TextInput label={t('inbounds.snellPsk')} required style={{ flex: 1 }} {...form.getInputProps('snell_psk')} />
              <Tooltip label={t('inbounds.generateKey')}><ActionIcon variant="light" size="input-sm" aria-label={t('inbounds.generateKey')} onClick={genPSK}><IconRefresh size={16} /></ActionIcon></Tooltip>
              <Select style={{ flex: 1 }} label={t('inbounds.snellVersion')} data={[{ value: '5', label: 'v5' }, { value: '4', label: 'v4' }]} allowDeselect={false} value={String(v.snell_version)} onChange={(x) => form.setFieldValue('snell_version', Number(x) || 5)} />
              <Select style={{ flex: 1 }} label={t('inbounds.snellObfs')} data={[{ value: '', label: t('common.none') }, { value: 'http', label: 'http' }, { value: 'tls', label: 'tls' }]} allowDeselect={false} {...form.getInputProps('snell_obfs')} />
              {v.snell_obfs && <TextInput label={t('inbounds.snellObfsHost')} placeholder="www.bing.com" {...form.getInputProps('snell_obfs_host')} />}
            </Group>
          </Card>
        )}
        {v.protocol === 'mieru' && mieruStrategyOf(v.traffic_pattern) === 'custom' && (
          <JsonInput label={t('inbounds.trafficPattern')} description={t('inbounds.trafficPatternHint')} autosize minRows={6} maxRows={18} formatOnBlur {...form.getInputProps('traffic_pattern')} />
        )}

        {!selectedIngress && !newIngress && (
          <Group grow align="flex-start">
            <TextInput label={t('inbounds.displayHost')} description={t('inbounds.displayHint')} {...form.getInputProps('display_host')} />
            <NumberInput label={t('inbounds.displayPort')} min={0} max={65535} {...form.getInputProps('display_port')} />
          </Group>
        )}

        <Button variant="subtle" size="xs" onClick={() => setAdvanced((a) => !a)} style={{ alignSelf: 'flex-start' }}>{advanced ? t('inbounds.hideAdvanced') : t('inbounds.showAdvanced')}</Button>
        <Collapse in={advanced}>
          <JsonInput label={t('inbounds.extra')} description={t('inbounds.extraHint')} autosize minRows={3} formatOnBlur {...form.getInputProps('extra')} />
        </Collapse>

        <Group justify="flex-end"><Button variant="default" onClick={onCancel}>{t('common.cancel')}</Button><Button type="submit" loading={busy}>{t('common.save')}</Button></Group>
      </Stack>
    </form>
  )
}
