import { Button, Group, NumberInput, TextInput, Tooltip } from '@mantine/core'
import type { useForm } from '@mantine/form'
import { useTranslation } from 'react-i18next'
import type { Ingress, IngressInput } from '../lib/api'

export type IngressValues = { Name: string; BindIP: string; LineIP: string; EntryHost: string; EntryDomain: string; PortFrom: number | string; PortTo: number | string; PortOffset: number | string; ReservedPorts: string }
export const parsePorts = (s: string) => s.split(/[\s,]+/).map((x) => Number(x)).filter((n) => n > 0 && n < 65536)
export const emptyIngress: IngressValues = { Name: 'IPLC', BindIP: '', LineIP: '', EntryHost: '', EntryDomain: '', PortFrom: '', PortTo: '', PortOffset: 0, ReservedPorts: '' }
export const ingressPayload = (v: IngressValues): IngressInput => ({ Name: v.Name, BindIP: v.BindIP, LineIP: v.LineIP, EntryHost: v.EntryHost, EntryDomain: v.EntryDomain, PortFrom: Number(v.PortFrom) || 0, PortTo: Number(v.PortTo) || 0, PortOffset: Number(v.PortOffset) || 0, ReservedPorts: parsePorts(v.ReservedPorts) })
export const ingressValues = (g: Ingress): IngressValues => ({ Name: g.name, BindIP: g.bind_ip, LineIP: g.line_ip, EntryHost: g.entry_host, EntryDomain: g.entry_domain ?? '', PortFrom: g.port_from || '', PortTo: g.port_to || '', PortOffset: g.port_offset, ReservedPorts: (g.reserved_ports ?? []).join(', ') })
// What share links advertise for a line: its domain when named, else the provider's entry.
export const clientHost = (g: Ingress) => g.entry_domain || g.entry_host

// The fields of one line ingress, shared by the page and the inbound recipe.
// derivedPool is nobrand's "derived-tail" policy: for a local IPv4 ending
// in N, port N×100 is reserved and N×100+1..N×100+99 is the automatic pool.
export const derivedPool = (bindIP: string) => {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(bindIP.trim())
  if (!m) return null
  const n = Number(m[4])
  if (n < 1 || n > 254) return null
  const base = n * 100
  if (base + 99 > 65535 || base < 1024) return null
  return { reserved: base, from: base + 1, to: base + 99 }
}

export function IngressFields({ form }: { form: ReturnType<typeof useForm<IngressValues>> }) {
  const { t } = useTranslation()
  return (
    <>
      <Group grow>
        <TextInput label={t('ingress.name')} required {...form.getInputProps('Name')} />
        <TextInput label={t('ingress.bindIP')} description={t('ingress.bindIPHint')} placeholder="10.10.0.2" {...form.getInputProps('BindIP')} />
      </Group>
      <Group grow>
        <TextInput label={t('ingress.lineIP')} description={t('ingress.lineIPHint')} placeholder="198.51.100.20" {...form.getInputProps('LineIP')} />
        <TextInput label={t('ingress.entryHost')} description={t('ingress.entryHostHint')} placeholder="203.0.113.30" {...form.getInputProps('EntryHost')} />
      </Group>
      <TextInput label={t('ingress.entryDomain')} description={t('ingress.entryDomainHint')} placeholder="iplc.node.example.com" {...form.getInputProps('EntryDomain')} />
      <Group grow align="flex-end">
        <NumberInput label={t('ingress.portFrom')} min={1} max={65535} placeholder="17701" {...form.getInputProps('PortFrom')} />
        <NumberInput label={t('ingress.portTo')} min={1} max={65535} placeholder="17799" {...form.getInputProps('PortTo')} />
        <NumberInput label={t('ingress.portOffset')} description={t('ingress.portOffsetHint')} {...form.getInputProps('PortOffset')} />
      </Group>
      <Group align="flex-end" gap="xs">
        <TextInput flex={1} label={t('ingress.reserved')} description={t('ingress.reservedHint')} placeholder="17700" {...form.getInputProps('ReservedPorts')} />
        <Tooltip label={t('ingress.deriveHint')}><Button size="xs" variant="light" mb={2} disabled={!derivedPool(form.values.BindIP)} onClick={() => { const d = derivedPool(form.values.BindIP); if (d) form.setValues({ PortFrom: d.from, PortTo: d.to, ReservedPorts: String(d.reserved) }) }}>{t('ingress.derive')}</Button></Tooltip>
      </Group>
    </>
  )
}
