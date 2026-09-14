import { ActionIcon, Badge, Button, Card, Code, Drawer, Group, Modal, MultiSelect, NumberInput, Progress, Stack, Switch, Table, Text, TextInput, Title } from '@mantine/core'
import { DateInput } from '@mantine/dates'
import { useForm } from '@mantine/form'
import { modals } from '@mantine/modals'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconPencil, IconPlus, IconTrash, IconQrcode } from '@tabler/icons-react'
import { QRCodeSVG } from 'qrcode.react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, type Inbound, type Link, type User } from '../lib/api'
import { useAuth } from '../lib/auth'
import { bytes, when } from '../lib/format'
import { toast } from '../lib/notify'
import { PageHeader } from '../components/PageHeader'
import { Copy } from '../components/Copy'

type Values = { name: string; uuid: string; password: string; enabled: boolean; quota_gib: number; expires_at: Date | null; inbound_tags: string[] }
const empty: Values = { name: '', uuid: '', password: '', enabled: true, quota_gib: 0, expires_at: null, inbound_tags: [] }

export default function UsersPage() {
  const { t } = useTranslation()
  const { me } = useAuth()
  const qc = useQueryClient()
  const readOnly = me?.mode !== 'local' || !!me?.fixed
  const q = useQuery({ queryKey: ['users'], queryFn: () => api.get<User[]>('/api/users'), refetchInterval: 10_000 })
  const inbounds = useQuery({ queryKey: ['inbounds'], queryFn: () => api.get<Inbound[]>('/api/inbounds') })
  const [editing, setEditing] = useState<User | 'new' | null>(null)
  const [sel, setSel] = useState<User | null>(null)
  const [qr, setQr] = useState<Link | null>(null)
  const links = useQuery({ queryKey: ['links', sel?.id], queryFn: () => api.get<{ links: Link[]; sub_url: string }>(`/api/users/${sel!.id}/links`), enabled: sel !== null })
  const invalidate = () => { qc.invalidateQueries({ queryKey: ['users'] }); qc.invalidateQueries({ queryKey: ['status'] }); qc.invalidateQueries({ queryKey: ['links'] }) }
  const form = useForm<Values>({ initialValues: empty, validate: { name: (v) => (v.trim() ? null : t('form.required')) } })
  const payload = (v: Values) => ({ name: v.name, uuid: v.uuid, password: v.password, enabled: v.enabled, quota_bytes: Math.round(v.quota_gib * 2 ** 30), expires_at: v.expires_at ? v.expires_at.toISOString() : null, inbound_tags: v.inbound_tags })
  const save = useMutation({
    mutationFn: (v: Values) => editing === 'new' ? api.post('/api/users', payload(v)) : api.put(`/api/users/${(editing as User).id}`, payload(v)),
    onSuccess: () => { toast.ok(t('common.saved')); setEditing(null); invalidate() }, onError: toast.err,
  })
  const del = useMutation({ mutationFn: (id: number) => api.del(`/api/users/${id}`), onSuccess: () => { toast.ok(t('common.deleted')); setSel(null); invalidate() }, onError: toast.err })
  const reset = useMutation({ mutationFn: (id: number) => api.post(`/api/users/${id}/reset`), onSuccess: () => { toast.ok(t('common.saved')); invalidate() }, onError: toast.err })
  const rotate = useMutation({ mutationFn: (id: number) => api.post(`/api/users/${id}/rotate`), onSuccess: () => { toast.ok(t('common.saved')); invalidate() }, onError: toast.err })
  const open = (u: User | 'new') => {
    form.setValues(u === 'new' ? empty : { name: u.name, uuid: u.uuid, password: u.password, enabled: u.enabled, quota_gib: u.quota_bytes / 2 ** 30, expires_at: u.expires_at ? new Date(u.expires_at) : null, inbound_tags: u.inbound_tags ?? [] })
    setEditing(u)
  }
  // Snell has one shared PSK, so a per-user restriction cannot apply to it.
  const tagOptions = (inbounds.data ?? []).filter((ib) => ib.protocol !== 'snell').map((ib) => ({ value: ib.tag, label: ib.remark ? `${ib.tag} · ${ib.remark}` : ib.tag }))
  return (
    <>
      <PageHeader title={t('users.title')} subtitle={t('users.subtitle')} actions={!readOnly && <Button leftSection={<IconPlus size={16} />} onClick={() => open('new')}>{t('users.create')}</Button>} />
      <Card p={0}>
        <Table>
          <Table.Thead><Table.Tr>
            <Table.Th>{t('users.name')}</Table.Th><Table.Th>{t('users.usage')}</Table.Th><Table.Th>{t('users.expires')}</Table.Th><Table.Th>{t('users.online')}</Table.Th><Table.Th>{t('users.status')}</Table.Th><Table.Th />
          </Table.Tr></Table.Thead>
          <Table.Tbody>
            {(q.data ?? []).map((u) => (
              <Table.Tr key={u.id} style={{ cursor: 'pointer' }} onClick={() => setSel(u)}>
                <Table.Td><Text fw={600} size="sm">{u.name}</Text><Text size="xs" c="dimmed" ff="monospace">{u.uuid.slice(0, 8)}…</Text></Table.Td>
                <Table.Td w={200}><Text size="xs">{bytes(u.up + u.down)}{u.quota_bytes ? ` / ${bytes(u.quota_bytes)}` : ''}</Text>{u.quota_bytes > 0 && <Progress size="xs" mt={4} value={Math.min(100, ((u.up + u.down) / u.quota_bytes) * 100)} color={(u.up + u.down) / u.quota_bytes > 0.9 ? 'orange' : 'brand'} />}</Table.Td>
                <Table.Td><Text size="sm">{u.expires_at ? when(u.expires_at).split(',')[0] : t('users.never')}</Text></Table.Td>
                <Table.Td>{u.online.length > 0 ? <Badge color="teal">{u.online.length}</Badge> : <Text size="sm" c="dimmed">—</Text>}</Table.Td>
                <Table.Td><Badge color={!u.enabled ? 'gray' : u.usable ? 'teal' : 'orange'}>{!u.enabled ? t('common.disabled') : u.usable ? t('users.active') : t('users.blocked')}</Badge></Table.Td>
                <Table.Td onClick={(e) => e.stopPropagation()}><Group gap={4} justify="flex-end" wrap="nowrap">
                  {!readOnly && <ActionIcon variant="subtle" color="gray" onClick={() => open(u)}><IconPencil size={16} /></ActionIcon>}
                  {!readOnly && <ActionIcon variant="subtle" color="red" onClick={() => modals.openConfirmModal({ title: t('common.delete'), children: <Text size="sm">{t('common.confirmDelete')}</Text>, labels: { confirm: t('common.delete'), cancel: t('common.cancel') }, confirmProps: { color: 'red' }, onConfirm: () => del.mutate(u.id) })}><IconTrash size={16} /></ActionIcon>}
                </Group></Table.Td>
              </Table.Tr>
            ))}
            {(q.data ?? []).length === 0 && <Table.Tr><Table.Td colSpan={6}><Text c="dimmed" ta="center" py="lg">{readOnly ? t('common.empty') : t('users.emptyHint')}</Text></Table.Td></Table.Tr>}
          </Table.Tbody>
        </Table>
      </Card>

      <Modal opened={editing !== null} onClose={() => setEditing(null)} title={editing === 'new' ? t('users.create') : t('common.edit')}>
        <form onSubmit={form.onSubmit((v) => save.mutate(v))}><Stack>
          <TextInput label={t('users.name')} required {...form.getInputProps('name')} />
          <Group grow>
            <TextInput label="UUID" placeholder={t('users.autoGenerated')} {...form.getInputProps('uuid')} />
            <TextInput label={t('users.password')} placeholder={t('users.passwordHint')} {...form.getInputProps('password')} />
          </Group>
          <Group grow>
            <NumberInput label={t('users.quota')} description={t('users.quotaHint')} min={0} decimalScale={2} {...form.getInputProps('quota_gib')} />
            <DateInput label={t('users.expires')} description={t('users.expiresHint')} clearable {...form.getInputProps('expires_at')} />
          </Group>
          <MultiSelect label={t('users.inbounds')} description={t('users.inboundsHint')} data={tagOptions} {...form.getInputProps('inbound_tags')} />
          <Switch label={t('common.enabled')} {...form.getInputProps('enabled', { type: 'checkbox' })} />
          <Group justify="flex-end"><Button variant="default" onClick={() => setEditing(null)}>{t('common.cancel')}</Button><Button type="submit" loading={save.isPending}>{t('common.save')}</Button></Group>
        </Stack></form>
      </Modal>

      <Drawer opened={sel !== null} onClose={() => setSel(null)} position="right" size="lg" title={sel?.name}>
        {sel && (
          <Stack gap="lg">
            <Group gap="xl">
              <div><Text size="xs" c="dimmed">UUID</Text><Group gap={4}><Code>{sel.uuid}</Code><Copy value={sel.uuid} /></Group></div>
              <div><Text size="xs" c="dimmed">{t('users.usage')}</Text><Text size="sm">↑ {bytes(sel.up)} · ↓ {bytes(sel.down)}</Text></div>
              <div><Text size="xs" c="dimmed">{t('users.createdAt')}</Text><Text size="sm">{when(sel.created_at)}</Text></div>
            </Group>
            {sel.online.length > 0 && <div><Text size="xs" c="dimmed">{t('users.onlineIps')}</Text><Group gap={6} mt={4}>{sel.online.map((ip) => <Badge key={ip} variant="light" color="teal">{ip}</Badge>)}</Group></div>}
            <div>
              <Text size="xs" c="dimmed">{t('users.subUrl')}</Text>
              <Group gap={4} wrap="nowrap"><Code style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{links.data?.sub_url ?? '…'}</Code>{links.data && <Copy value={links.data.sub_url} />}</Group>
              <Text size="xs" c="dimmed" mt={4}>{t('users.subHint')}</Text>
            </div>
            <div>
              <Title order={6} mb="xs">{t('users.links')}</Title>
              <Stack gap="xs">
                {(links.data?.links ?? []).map((l) => (
                  <Group key={l.tag} gap={4} wrap="nowrap">
                    <Badge variant="outline" color="gray" miw={90}>{l.tag}</Badge>
                    <Code style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{l.uri}</Code>
                    <Copy value={l.uri} />
                    <ActionIcon variant="subtle" color="gray" size="sm" onClick={() => setQr(l)}><IconQrcode size={14} /></ActionIcon>
                  </Group>
                ))}
                {links.data && links.data.links.length === 0 && <Text size="sm" c="dimmed">{t('users.noLinks')}</Text>}
              </Stack>
            </div>
            {!readOnly && (
              <Group justify="space-between">
                <Group gap="xs">
                  <Button size="xs" variant="default" onClick={() => reset.mutate(sel.id)}>{t('users.resetTraffic')}</Button>
                  <Button size="xs" variant="default" color="orange" onClick={() => modals.openConfirmModal({ title: t('users.rotate'), children: <Text size="sm">{t('users.rotateHint')}</Text>, labels: { confirm: t('common.confirm'), cancel: t('common.cancel') }, onConfirm: () => rotate.mutate(sel.id) })}>{t('users.rotate')}</Button>
                </Group>
                <Button size="xs" onClick={() => open(sel)}>{t('common.edit')}</Button>
              </Group>
            )}
          </Stack>
        )}
      </Drawer>
      <Modal opened={qr !== null} onClose={() => setQr(null)} title={qr?.name} size="sm">
        {qr && <Stack align="center"><div style={{ background: '#fff', padding: 12, borderRadius: 8 }}><QRCodeSVG value={qr.uri} size={240} /></div><Code block style={{ wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>{qr.uri}</Code></Stack>}
      </Modal>
    </>
  )
}
