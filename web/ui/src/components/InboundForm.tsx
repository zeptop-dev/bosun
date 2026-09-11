import { ActionIcon, Button, Card, Collapse, Group, JsonInput, NumberInput, Select, SimpleGrid, Stack, Switch, Text, TextInput, Tooltip, UnstyledButton } from '@mantine/core'
import { useForm } from '@mantine/form'
import { IconRefresh } from '@tabler/icons-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, type Inbound } from '../lib/api'
import { toast } from '../lib/notify'

const protocols = ['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'anytls', 'mieru', 'socks', 'http']
const cores = ['', 'singbox', 'xray', 'mita', 'hysteria']
const transports = ['tcp', 'ws', 'grpc', 'httpupgrade', 'http', 'xhttp']
const ciphers = ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305', 'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'none']

// Values is the flat form model; toInbound folds it back into spec.Inbound JSON.
export type Values = {
  tag: string; remark: string; protocol: string; listen: string; port: number; core: string; enabled: boolean
  display_host: string; display_port: number
  tls: 'none' | 'tls' | 'reality'; server_name: string; reality_private: string; reality_public: string; reality_short: string; handshake_server: string; handshake_port: number
  transport: string; path: string; host: string; service_name: string; xhttp_mode: string
  flow: string; cipher: string; server_key: string; obfs: string; obfs_password: string; up_mbps: number; down_mbps: number
  congestion_control: string; mieru_transport: string; traffic_pattern: string
  extra: string
}

export const empty: Values = {
  tag: '', remark: '', protocol: 'vless', listen: '', port: 443, core: '', enabled: true, display_host: '', display_port: 0,
  tls: 'none', server_name: '', reality_private: '', reality_public: '', reality_short: '', handshake_server: '', handshake_port: 443,
  transport: 'tcp', path: '', host: '', service_name: '', xhttp_mode: '',
  flow: '', cipher: '2022-blake3-aes-128-gcm', server_key: '', obfs: '', obfs_password: '', up_mbps: 0, down_mbps: 0,
  congestion_control: 'bbr', mieru_transport: 'TCP', traffic_pattern: '', extra: '{}',
}

const known = new Set(['tag', 'remark', 'protocol', 'listen', 'port', 'core', 'enabled', 'display_host', 'display_port', 'tls', 'transport', 'flow', 'cipher', 'server_key', 'obfs', 'obfs_password', 'up_mbps', 'down_mbps', 'congestion_control', 'mieru_transport', 'traffic_pattern', 'assigned_core', 'scoped_users', 'users'])

export function toValues(ib?: Inbound): Values {
  if (!ib) return empty
  const extra: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(ib)) if (!known.has(k)) extra[k] = v
  const tlsMode = ib.tls?.mode === 2 ? 'reality' : ib.tls?.mode === 1 ? 'tls' : 'none'
  return {
    ...empty,
    tag: ib.tag, remark: ib.remark ?? '', protocol: ib.protocol, listen: ib.listen ?? '', port: ib.port, core: ib.core ?? '', enabled: ib.enabled,
    display_host: ib.display_host ?? '', display_port: ib.display_port ?? 0,
    tls: tlsMode, server_name: ib.tls?.server_name ?? '', reality_private: ib.tls?.reality?.private_key ?? '', reality_public: ib.tls?.reality?.public_key ?? '',
    reality_short: ib.tls?.reality?.short_ids?.[0] ?? '', handshake_server: ib.tls?.reality?.handshake_server ?? '', handshake_port: ib.tls?.reality?.handshake_port ?? 443,
    transport: ib.transport?.type ?? 'tcp', path: ib.transport?.path ?? '', host: ib.transport?.host ?? '', service_name: ib.transport?.service_name ?? '', xhttp_mode: ib.transport?.mode ?? '',
    flow: ib.flow ?? '', cipher: ib.cipher ?? empty.cipher, server_key: ib.server_key ?? '', obfs: ib.obfs ?? '', obfs_password: ib.obfs_password ?? '',
    up_mbps: ib.up_mbps ?? 0, down_mbps: ib.down_mbps ?? 0, congestion_control: ib.congestion_control ?? 'bbr', mieru_transport: ib.mieru_transport ?? 'TCP', traffic_pattern: ib.traffic_pattern ?? '',
    extra: JSON.stringify(extra, null, 2),
  }
}

export function toInbound(v: Values): Record<string, unknown> {
  const out: Record<string, unknown> = { ...JSON.parse(v.extra || '{}'), tag: v.tag, remark: v.remark, protocol: v.protocol, listen: v.listen, port: v.port, core: v.core, enabled: v.enabled, display_host: v.display_host, display_port: v.display_port }
  const stream = ['vless', 'vmess', 'trojan', 'shadowsocks', 'anytls', 'socks', 'http'].includes(v.protocol)
  const quic = ['hysteria2', 'tuic'].includes(v.protocol)
  if (v.tls === 'reality') out.tls = { mode: 2, server_name: v.server_name, reality: { private_key: v.reality_private, public_key: v.reality_public, short_ids: v.reality_short ? [v.reality_short] : [], handshake_server: v.handshake_server || v.server_name, handshake_port: v.handshake_port || 443 } }
  else if (v.tls === 'tls' || quic) out.tls = { mode: 1, server_name: v.server_name }
  if (stream && v.transport !== 'tcp') out.transport = { type: v.transport, path: v.path, host: v.host, service_name: v.service_name, mode: v.xhttp_mode }
  if (v.protocol === 'vless' && v.flow) out.flow = v.flow
  if (v.protocol === 'shadowsocks') { out.cipher = v.cipher; if (v.cipher.startsWith('2022')) out.server_key = v.server_key }
  if (v.protocol === 'hysteria2') { if (v.obfs) { out.obfs = v.obfs; out.obfs_password = v.obfs_password } if (v.up_mbps) out.up_mbps = v.up_mbps; if (v.down_mbps) out.down_mbps = v.down_mbps }
  if (v.protocol === 'tuic') out.congestion_control = v.congestion_control
  if (v.protocol === 'mieru') { out.mieru_transport = v.mieru_transport; if (v.traffic_pattern) out.traffic_pattern = v.traffic_pattern }
  return out
}

const recipes: { key: string; values: Partial<Values> }[] = [
  { key: 'vlessReality', values: { protocol: 'vless', port: 443, tls: 'reality', server_name: 'www.apple.com', handshake_server: 'www.apple.com', flow: 'xtls-rprx-vision', transport: 'tcp' } },
  { key: 'hysteria2', values: { protocol: 'hysteria2', port: 8443, tls: 'tls', obfs: 'salamander', up_mbps: 100, down_mbps: 500 } },
  { key: 'mieru', values: { protocol: 'mieru', port: 24450, tls: 'none', mieru_transport: 'TCP' } },
  { key: 'ss2022', values: { protocol: 'shadowsocks', port: 8388, tls: 'none', cipher: '2022-blake3-aes-128-gcm' } },
  { key: 'trojanWs', values: { protocol: 'trojan', port: 443, tls: 'tls', transport: 'ws', path: '/trojan' } },
  { key: 'anytls', values: { protocol: 'anytls', port: 8444, tls: 'tls' } },
]

export function InboundForm({ initial, onSubmit, busy, onCancel }: { initial: Values; onSubmit: (v: Record<string, unknown>) => void; busy: boolean; onCancel: () => void }) {
  const { t } = useTranslation()
  const [advanced, setAdvanced] = useState(false)
  const form = useForm<Values>({
    initialValues: initial,
    validate: {
      tag: (v) => (v.trim() ? null : t('form.required')),
      port: (v) => (v > 0 && v < 65536 ? null : t('form.port')),
      extra: (v) => { try { JSON.parse(v || '{}'); return null } catch { return t('form.json') } },
      reality_private: (v, all) => (all.tls === 'reality' && !v ? t('form.required') : null),
      server_key: (v, all) => (all.protocol === 'shadowsocks' && all.cipher.startsWith('2022') && !v ? t('form.required') : null),
    },
  })
  const v = form.values
  const stream = ['vless', 'vmess', 'trojan', 'shadowsocks', 'anytls', 'socks', 'http'].includes(v.protocol)
  const quic = ['hysteria2', 'tuic'].includes(v.protocol)
  const tlsCapable = stream && v.protocol !== 'shadowsocks'
  const genReality = async () => {
    try { const k = await api.post<{ private_key: string; public_key: string; short_id: string }>('/api/keys/reality'); form.setValues({ reality_private: k.private_key, reality_public: k.public_key, reality_short: v.reality_short || k.short_id }) } catch (e) { toast.err(e) }
  }
  const genKey = async () => {
    try { const k = await api.post<{ key: string }>(`/api/keys/ss2022?cipher=${encodeURIComponent(v.cipher)}`); form.setFieldValue('server_key', k.key) } catch (e) { toast.err(e) }
  }
  const genPassword = async () => {
    try { const k = await api.post<{ password: string }>('/api/keys/password'); form.setFieldValue('obfs_password', k.password) } catch (e) { toast.err(e) }
  }
  const apply = (r: (typeof recipes)[number]) => {
    form.setValues({ ...empty, ...r.values, tag: v.tag || r.values.protocol!, remark: v.remark, enabled: true })
    if (r.values.tls === 'reality') void genReality()
    if (r.values.cipher?.startsWith('2022')) void genKey()
    if (r.values.obfs) void genPassword()
  }
  return (
    <form onSubmit={form.onSubmit((vals) => onSubmit(toInbound(vals)))}>
      <Stack>
        <div>
          <Text size="sm" fw={600}>{t('inbounds.recipe')}</Text>
          <Text size="xs" c="dimmed" mb="xs">{t('inbounds.recipeHint')}</Text>
          <SimpleGrid cols={{ base: 2, sm: 3 }} spacing="xs">
            {recipes.map((r) => (
              <UnstyledButton key={r.key} onClick={() => apply(r)}>
                <Card p="sm" style={{ height: '100%' }}>
                  <Text size="sm" fw={600}>{t(`inbounds.recipes.${r.key}`)}</Text>
                  <Text size="xs" c="dimmed">{t(`inbounds.recipes.${r.key}Desc`)}</Text>
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
        <Group grow>
          <TextInput label={t('inbounds.listen')} placeholder="::" {...form.getInputProps('listen')} />
          <NumberInput label={t('inbounds.port')} min={1} max={65535} required {...form.getInputProps('port')} />
          <Select label={t('inbounds.core')} data={cores.map((c) => ({ value: c, label: c || t('inbounds.coreAuto') }))} allowDeselect={false} {...form.getInputProps('core')} />
          <Switch mt={24} label={t('inbounds.enabled')} {...form.getInputProps('enabled', { type: 'checkbox' })} />
        </Group>

        {(tlsCapable || quic) && (
          <Card p="sm">
            <Group grow align="flex-start">
              {tlsCapable
                ? <Select label={t('inbounds.tls')} data={[{ value: 'none', label: t('inbounds.tlsNone') }, { value: 'tls', label: 'TLS' }, { value: 'reality', label: 'REALITY' }]} allowDeselect={false} {...form.getInputProps('tls')} />
                : <TextInput label={t('inbounds.tls')} value="TLS" disabled />}
              {(v.tls !== 'none' || quic) && <TextInput label={t('inbounds.serverName')} description={v.tls === 'reality' ? t('inbounds.serverNameReality') : t('inbounds.serverNameTls')} {...form.getInputProps('server_name')} />}
            </Group>
            {v.tls === 'reality' && tlsCapable && (
              <Stack gap="xs" mt="sm">
                <Group grow align="flex-end">
                  <TextInput label={t('inbounds.realityPrivate')} required {...form.getInputProps('reality_private')} />
                  <TextInput label={t('inbounds.realityPublic')} {...form.getInputProps('reality_public')} />
                  <Tooltip label={t('inbounds.generate')}><ActionIcon variant="light" size="lg" onClick={genReality}><IconRefresh size={16} /></ActionIcon></Tooltip>
                </Group>
                <Group grow>
                  <TextInput label={t('inbounds.shortId')} {...form.getInputProps('reality_short')} />
                  <TextInput label={t('inbounds.handshakeServer')} placeholder={v.server_name} {...form.getInputProps('handshake_server')} />
                  <NumberInput label={t('inbounds.handshakePort')} {...form.getInputProps('handshake_port')} />
                </Group>
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
          <Group grow align="flex-end">
            <Select label={t('inbounds.cipher')} data={ciphers} allowDeselect={false} {...form.getInputProps('cipher')} />
            {v.cipher.startsWith('2022') && <TextInput label={t('inbounds.serverKey')} required {...form.getInputProps('server_key')} />}
            {v.cipher.startsWith('2022') && <Tooltip label={t('inbounds.generate')}><ActionIcon variant="light" size="lg" onClick={genKey}><IconRefresh size={16} /></ActionIcon></Tooltip>}
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
          <Group grow>
            <Select label={t('inbounds.mieruTransport')} data={['TCP', 'UDP']} allowDeselect={false} {...form.getInputProps('mieru_transport')} />
            <TextInput label={t('inbounds.trafficPattern')} placeholder={t('inbounds.trafficPatternHint')} {...form.getInputProps('traffic_pattern')} />
          </Group>
        )}

        <Group grow>
          <TextInput label={t('inbounds.displayHost')} description={t('inbounds.displayHint')} {...form.getInputProps('display_host')} />
          <NumberInput label={t('inbounds.displayPort')} min={0} max={65535} {...form.getInputProps('display_port')} />
        </Group>

        <Button variant="subtle" size="xs" onClick={() => setAdvanced((a) => !a)} style={{ alignSelf: 'flex-start' }}>{advanced ? t('inbounds.hideAdvanced') : t('inbounds.showAdvanced')}</Button>
        <Collapse in={advanced}>
          <JsonInput label={t('inbounds.extra')} description={t('inbounds.extraHint')} autosize minRows={3} formatOnBlur {...form.getInputProps('extra')} />
        </Collapse>

        <Group justify="flex-end"><Button variant="default" onClick={onCancel}>{t('common.cancel')}</Button><Button type="submit" loading={busy}>{t('common.save')}</Button></Group>
      </Stack>
    </form>
  )
}
