import { ActionIcon, Badge, Button, Card, Code, Group, Select, Stack, Text, TextInput, Textarea } from '@mantine/core'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconPlus, IconTrash } from '@tabler/icons-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, type Inbound, type Outbound, type Remote, type Routing } from '../lib/api'
import { useAuth } from '../lib/auth'
import { toast } from '../lib/notify'
import { PageHeader } from '../components/PageHeader'

// Landing outbounds and route rules: paste a share link to add an exit, then
// send everything (default) or specific inbounds to it.
export default function RoutingPage({ embedded }: { embedded?: boolean }) {
  const { t } = useTranslation()
  const { me } = useAuth()
  const qc = useQueryClient()
  const readOnly = me?.mode !== 'local' || !!me?.fixed
  const q = useQuery({ queryKey: ['routing'], queryFn: () => api.get<Routing>('/api/routing') })
  const inbounds = useQuery({ queryKey: ['inbounds'], queryFn: () => api.get<Inbound[]>('/api/inbounds') })
  const inboundTags = (inbounds.data ?? []).map((ib) => ib.tag)
  const [nr, setNr] = useState<Routing>({ outbounds: [], routes: [], default_outbound: '' })
  useEffect(() => { if (q.data) setNr({ outbounds: q.data.outbounds ?? [], routes: q.data.routes ?? [], default_outbound: q.data.default_outbound ?? '' }) }, [q.data])
  const save = useMutation({ mutationFn: (v: Routing) => api.put('/api/routing', v), onSuccess: () => { toast.ok(t('common.saved')); qc.invalidateQueries({ queryKey: ['routing'] }); qc.invalidateQueries({ queryKey: ['status'] }) }, onError: toast.err })
  const [link, setLink] = useState('')
  const [tag, setTag] = useState('')
  const parse = useMutation({ mutationFn: () => api.post<{ nodes: { name: string; protocol: string; remote: Remote }[] }>('/api/routing/parse', { text: link }), onSuccess: (r) => {
    if (!r.nodes.length) { toast.err(new Error(t('routing.badLink'))); return }
    const n = r.nodes[0]
    const tg = (tag || n.name || n.protocol).replace(/[^\w.-]+/g, '-')
    setNr((cur) => ({ ...cur, outbounds: [...cur.outbounds, { tag: tg, remote: n.remote }] }))
    setLink(''); setTag('')
  }, onError: toast.err })
  const tags = nr.outbounds.map((o) => o.tag)
  const outboundOptions = [{ value: 'direct', label: t('routing.direct') }, { value: 'block', label: t('routing.block') }, ...tags.map((x) => ({ value: x, label: x }))]
  const describe = (o: Outbound) => o.remote ? `${o.remote.settings.protocol} ${o.remote.host}:${o.remote.port}` : `${o.protocol} (${t('routing.raw')})`
  return (
    <>
      {embedded ? <Text size="xs" c="dimmed" mb="sm" maw={720}>{t('routing.hint')}</Text> : <PageHeader title={t('routing.title')} subtitle={t('routing.hint')} />}
      <Card>
        <Stack gap="xs">
          <Text size="sm" fw={600}>{t('routing.outbounds')}</Text>
          {nr.outbounds.map((o, i) => (
            <Group key={i} justify="space-between" wrap="nowrap">
              <Group gap="xs" wrap="nowrap" style={{ minWidth: 0 }}><Code>{o.tag}</Code><Text size="sm" truncate>{describe(o)}</Text>{o.proxy_tag && <Badge size="xs" variant="light">{t('routing.via', { tag: o.proxy_tag })}</Badge>}{nr.default_outbound === o.tag && <Badge size="xs" color="teal">{t('routing.isDefault')}</Badge>}</Group>
              <Group gap={4} wrap="nowrap">
                <Select size="xs" w={150} placeholder={t('routing.chain')} disabled={readOnly} data={[{ value: '', label: t('routing.noChain') }, ...tags.filter((x) => x !== o.tag).map((x) => ({ value: x, label: t('routing.via', { tag: x }) }))]} value={o.proxy_tag ?? ''} allowDeselect={false} onChange={(v) => setNr((cur) => ({ ...cur, outbounds: cur.outbounds.map((x, j) => (j === i ? { ...x, proxy_tag: v || undefined } : x)) }))} />
                {!readOnly && <ActionIcon variant="subtle" color="red" onClick={() => setNr((cur) => ({ ...cur, outbounds: cur.outbounds.filter((_, j) => j !== i), routes: cur.routes.filter((r) => r.value !== o.tag), default_outbound: cur.default_outbound === o.tag ? '' : cur.default_outbound }))}><IconTrash size={14} /></ActionIcon>}
              </Group>
            </Group>
          ))}
          {nr.outbounds.length === 0 && <Text size="xs" c="dimmed">{t('routing.empty')}</Text>}
          {!readOnly && (
            <Group align="flex-end" wrap="nowrap">
              <TextInput label={t('routing.addFromLink')} placeholder="vless://… / ss://… / socks://user:pass@host:port" style={{ flex: 3 }} value={link} onChange={(e) => setLink(e.currentTarget.value)} />
              <TextInput label={t('routing.tag')} placeholder="exit-us" style={{ flex: 1 }} value={tag} onChange={(e) => setTag(e.currentTarget.value)} />
              <Button size="xs" mb={2} variant="light" leftSection={<IconPlus size={14} />} disabled={!link.trim()} loading={parse.isPending} onClick={() => parse.mutate()}>{t('routing.add')}</Button>
            </Group>
          )}
          <Textarea label={t('routing.rawJSON')} description={t('routing.rawHint')} autosize minRows={2} ff="monospace" disabled={readOnly} value={JSON.stringify(nr.outbounds.filter((o) => !o.remote), null, 0)} onBlur={(e) => { try { const raw = JSON.parse(e.currentTarget.value || '[]') as Outbound[]; setNr((cur) => ({ ...cur, outbounds: [...cur.outbounds.filter((o) => o.remote), ...raw] })) } catch { toast.err(new Error(t('form.json'))) } }} />
          <Select label={t('routing.default')} description={t('routing.defaultHint')} disabled={readOnly} data={[{ value: '', label: t('routing.direct') }, ...tags.map((x) => ({ value: x, label: x }))]} value={nr.default_outbound} allowDeselect={false} onChange={(v) => setNr((cur) => ({ ...cur, default_outbound: v ?? '' }))} />
          <Text size="sm" fw={600} mt="xs">{t('routing.rules')}</Text>
          {nr.routes.map((r, i) => (
            <Group key={i} align="flex-end" wrap="nowrap">
              <TextInput label={i === 0 ? t('routing.match') : undefined} description={i === 0 ? t('routing.matchHint') : undefined} style={{ flex: 3 }} disabled={readOnly} value={r.match.join(', ')} onChange={(e) => setNr((cur) => ({ ...cur, routes: cur.routes.map((x, j) => (j === i ? { ...x, match: e.currentTarget.value.split(',').map((s) => s.trim()).filter(Boolean) } : x)) }))} />
              <Select label={i === 0 ? t('routing.to') : undefined} style={{ flex: 1 }} disabled={readOnly} data={outboundOptions} value={r.action === 'outbound' ? r.value ?? '' : r.action} allowDeselect={false} onChange={(v) => setNr((cur) => ({ ...cur, routes: cur.routes.map((x, j) => (j === i ? (v === 'direct' || v === 'block' ? { match: x.match, action: v } : { match: x.match, action: 'outbound', value: v ?? '' }) : x)) }))} />
              {!readOnly && <ActionIcon variant="subtle" color="red" mb={4} onClick={() => setNr((cur) => ({ ...cur, routes: cur.routes.filter((_, j) => j !== i) }))}><IconTrash size={14} /></ActionIcon>}
            </Group>
          ))}
          {!readOnly && (
            <Group justify="space-between">
              <Group gap="xs">
                <Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={() => setNr((cur) => ({ ...cur, routes: [...cur.routes, { match: [], action: 'direct' }] }))}>{t('routing.addRule')}</Button>
                {inboundTags.map((ib) => <Button key={ib} size="xs" variant="subtle" onClick={() => setNr((cur) => ({ ...cur, routes: [...cur.routes, { match: [`inbound:${ib}`], action: tags[0] ? 'outbound' : 'direct', value: tags[0] }] }))}>{t('routing.routeInbound', { tag: ib })}</Button>)}
              </Group>
              <Button size="xs" loading={save.isPending} onClick={() => save.mutate(nr)}>{t('common.save')}</Button>
            </Group>
          )}
        </Stack>
      </Card>
    </>
  )
}
