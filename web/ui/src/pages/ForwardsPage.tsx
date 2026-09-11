import { ActionIcon, Badge, Button, Card, Group, Modal, NumberInput, Select, Stack, Table, Text, TextInput } from '@mantine/core'
import { useForm } from '@mantine/form'
import { modals } from '@mantine/modals'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconPencil, IconPlus, IconTrash } from '@tabler/icons-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, type Forward } from '../lib/api'
import { useAuth } from '../lib/auth'
import { bytes } from '../lib/format'
import { toast } from '../lib/notify'
import { PageHeader } from '../components/PageHeader'

type Values = { tag: string; listen: string; port: number; protocol: string; target: string }
const empty: Values = { tag: '', listen: '', port: 10000, protocol: 'tcp', target: '' }

export default function ForwardsPage() {
  const { t } = useTranslation()
  const { me } = useAuth()
  const qc = useQueryClient()
  const readOnly = me?.mode !== 'local' || !!me?.fixed
  const q = useQuery({ queryKey: ['forwards'], queryFn: () => api.get<Forward[]>('/api/forwards'), refetchInterval: 5_000 })
  const [editing, setEditing] = useState<Forward | 'new' | null>(null)
  const form = useForm<Values>({ initialValues: empty, validate: { target: (v) => (/^.+:\d+$/.test(v) ? null : t('forwards.targetInvalid')), port: (v) => (v > 0 && v < 65536 ? null : t('form.port')) } })
  const invalidate = () => qc.invalidateQueries({ queryKey: ['forwards'] })
  const save = useMutation({
    mutationFn: (v: Values) => editing === 'new' ? api.post('/api/forwards', v) : api.put(`/api/forwards/${encodeURIComponent((editing as Forward).tag)}`, v),
    onSuccess: () => { toast.ok(t('common.saved')); setEditing(null); invalidate() }, onError: toast.err,
  })
  const del = useMutation({ mutationFn: (tag: string) => api.del(`/api/forwards/${encodeURIComponent(tag)}`), onSuccess: () => { toast.ok(t('common.deleted')); invalidate() }, onError: toast.err })
  const open = (f: Forward | 'new') => { form.setValues(f === 'new' ? empty : { tag: f.tag, listen: f.listen ?? '', port: f.port, protocol: f.protocol, target: f.target }); setEditing(f) }
  return (
    <>
      <PageHeader title={t('forwards.title')} subtitle={t('forwards.subtitle')} actions={!readOnly && <Button leftSection={<IconPlus size={16} />} onClick={() => open('new')}>{t('forwards.create')}</Button>} />
      <Card p={0}>
        <Table>
          <Table.Thead><Table.Tr>
            <Table.Th>{t('forwards.tag')}</Table.Th><Table.Th>{t('forwards.listen')}</Table.Th><Table.Th>{t('forwards.target')}</Table.Th><Table.Th>{t('forwards.health')}</Table.Th><Table.Th>{t('forwards.conns')}</Table.Th><Table.Th>{t('forwards.bytes')}</Table.Th><Table.Th />
          </Table.Tr></Table.Thead>
          <Table.Tbody>
            {(q.data ?? []).map((f) => (
              <Table.Tr key={f.tag}>
                <Table.Td><Text fw={600} size="sm">{f.tag}</Text></Table.Td>
                <Table.Td><Text size="sm">{f.listen || '0.0.0.0'}:{f.port} <Badge variant="outline" color="gray" ml={4}>{f.protocol}</Badge></Text></Table.Td>
                <Table.Td><Text size="sm" ff="monospace">{f.target}</Text></Table.Td>
                <Table.Td>{f.status ? <Badge color={f.status.up ? 'teal' : 'red'} title={f.status.last_error}>{f.status.up ? `${f.status.rtt_ms} ms` : t('forwards.down')}</Badge> : <Text size="sm" c="dimmed">—</Text>}</Table.Td>
                <Table.Td><Text size="sm">{f.status ? `${f.status.active_conn} / ${f.status.total_conn}` : '—'}</Text></Table.Td>
                <Table.Td><Text size="sm">{f.status ? `↑ ${bytes(f.status.bytes_in)} ↓ ${bytes(f.status.bytes_out)}` : '—'}</Text></Table.Td>
                <Table.Td><Group gap={4} justify="flex-end" wrap="nowrap">
                  {!readOnly && <ActionIcon variant="subtle" color="gray" onClick={() => open(f)}><IconPencil size={16} /></ActionIcon>}
                  {!readOnly && <ActionIcon variant="subtle" color="red" onClick={() => modals.openConfirmModal({ title: t('common.delete'), children: <Text size="sm">{t('common.confirmDelete')}</Text>, labels: { confirm: t('common.delete'), cancel: t('common.cancel') }, confirmProps: { color: 'red' }, onConfirm: () => del.mutate(f.tag) })}><IconTrash size={16} /></ActionIcon>}
                </Group></Table.Td>
              </Table.Tr>
            ))}
            {(q.data ?? []).length === 0 && <Table.Tr><Table.Td colSpan={7}><Text c="dimmed" ta="center" py="lg">{t('forwards.emptyHint')}</Text></Table.Td></Table.Tr>}
          </Table.Tbody>
        </Table>
      </Card>
      <Modal opened={editing !== null} onClose={() => setEditing(null)} title={editing === 'new' ? t('forwards.create') : t('common.edit')}>
        <form onSubmit={form.onSubmit((v) => save.mutate(v))}><Stack>
          <TextInput label={t('forwards.tag')} placeholder={t('forwards.tagHint')} {...form.getInputProps('tag')} />
          <Group grow>
            <TextInput label={t('forwards.listenAddr')} placeholder="0.0.0.0" {...form.getInputProps('listen')} />
            <NumberInput label={t('forwards.port')} min={1} max={65535} required {...form.getInputProps('port')} />
            <Select label={t('forwards.protocol')} data={['tcp', 'udp', 'both']} allowDeselect={false} {...form.getInputProps('protocol')} />
          </Group>
          <TextInput label={t('forwards.target')} description={t('forwards.targetHint')} placeholder="203.0.113.10:443" required {...form.getInputProps('target')} />
          <Group justify="flex-end"><Button variant="default" onClick={() => setEditing(null)}>{t('common.cancel')}</Button><Button type="submit" loading={save.isPending}>{t('common.save')}</Button></Group>
        </Stack></form>
      </Modal>
    </>
  )
}
