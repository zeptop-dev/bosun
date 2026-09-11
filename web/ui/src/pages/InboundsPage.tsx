import { ActionIcon, Badge, Button, Card, Group, Modal, Table, Text } from '@mantine/core'
import { modals } from '@mantine/modals'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconPencil, IconPlus, IconTrash } from '@tabler/icons-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, type Inbound } from '../lib/api'
import { useAuth } from '../lib/auth'
import { toast } from '../lib/notify'
import { PageHeader } from '../components/PageHeader'
import { InboundForm, toValues } from '../components/InboundForm'

export function tlsLabel(ib: Inbound) {
  if (!ib.tls || ib.tls.mode === 0) return ''
  return ib.tls.mode === 2 ? 'REALITY' : 'TLS'
}

export default function InboundsPage() {
  const { t } = useTranslation()
  const { me } = useAuth()
  const qc = useQueryClient()
  const readOnly = me?.mode !== 'local' || !!me?.fixed
  const q = useQuery({ queryKey: ['inbounds'], queryFn: () => api.get<Inbound[]>('/api/inbounds'), refetchInterval: 10_000 })
  const [editing, setEditing] = useState<Inbound | 'new' | null>(null)
  const invalidate = () => { qc.invalidateQueries({ queryKey: ['inbounds'] }); qc.invalidateQueries({ queryKey: ['status'] }) }
  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => editing === 'new' ? api.post('/api/inbounds', body) : api.put(`/api/inbounds/${encodeURIComponent((editing as Inbound).tag)}`, body),
    onSuccess: () => { toast.ok(t('common.saved')); setEditing(null); invalidate() }, onError: toast.err,
  })
  const del = useMutation({ mutationFn: (tag: string) => api.del(`/api/inbounds/${encodeURIComponent(tag)}`), onSuccess: () => { toast.ok(t('common.deleted')); invalidate() }, onError: toast.err })
  const toggle = useMutation({ mutationFn: (ib: Inbound) => api.put(`/api/inbounds/${encodeURIComponent(ib.tag)}`, { ...ib, enabled: !ib.enabled }), onSuccess: invalidate, onError: toast.err })
  return (
    <>
      <PageHeader title={t('inbounds.title')} subtitle={t('inbounds.subtitle')} actions={!readOnly && <Button leftSection={<IconPlus size={16} />} onClick={() => setEditing('new')}>{t('inbounds.create')}</Button>} />
      <Card p={0}>
        <Table>
          <Table.Thead><Table.Tr>
            <Table.Th>{t('inbounds.tag')}</Table.Th><Table.Th>{t('inbounds.protocol')}</Table.Th><Table.Th>{t('inbounds.port')}</Table.Th><Table.Th>{t('inbounds.security')}</Table.Th><Table.Th>{t('inbounds.core')}</Table.Th><Table.Th>{t('inbounds.enabled')}</Table.Th><Table.Th />
          </Table.Tr></Table.Thead>
          <Table.Tbody>
            {(q.data ?? []).map((ib) => (
              <Table.Tr key={ib.tag}>
                <Table.Td><Text fw={600} size="sm">{ib.tag}</Text>{ib.remark && <Text size="xs" c="dimmed">{ib.remark}</Text>}</Table.Td>
                <Table.Td><Badge variant="outline" color="gray">{ib.protocol}</Badge>{ib.transport?.type && ib.transport.type !== 'tcp' && <Badge ml={4} variant="outline" color="gray">{ib.transport.type}</Badge>}</Table.Td>
                <Table.Td>{ib.listen || '::'}:{ib.port}{ib.display_host && <Text size="xs" c="dimmed">→ {ib.display_host}:{ib.display_port || ib.port}</Text>}</Table.Td>
                <Table.Td>{tlsLabel(ib) && <Badge color={ib.tls?.mode === 2 ? 'grape' : 'blue'}>{tlsLabel(ib)}</Badge>}</Table.Td>
                <Table.Td><Text size="sm">{ib.assigned_core || ib.core || <Text span c="dimmed">{t('inbounds.coreAuto')}</Text>}</Text></Table.Td>
                <Table.Td><Badge color={ib.enabled ? 'teal' : 'gray'} style={{ cursor: readOnly ? 'default' : 'pointer' }} onClick={() => !readOnly && toggle.mutate(ib)}>{ib.enabled ? t('common.enabled') : t('common.disabled')}</Badge></Table.Td>
                <Table.Td><Group gap={4} justify="flex-end" wrap="nowrap">
                  {!readOnly && <ActionIcon variant="subtle" color="gray" onClick={() => setEditing(ib)}><IconPencil size={16} /></ActionIcon>}
                  {!readOnly && <ActionIcon variant="subtle" color="red" onClick={() => modals.openConfirmModal({ title: t('common.delete'), children: <Text size="sm">{t('common.confirmDelete')}</Text>, labels: { confirm: t('common.delete'), cancel: t('common.cancel') }, confirmProps: { color: 'red' }, onConfirm: () => del.mutate(ib.tag) })}><IconTrash size={16} /></ActionIcon>}
                </Group></Table.Td>
              </Table.Tr>
            ))}
            {(q.data ?? []).length === 0 && <Table.Tr><Table.Td colSpan={7}><Text c="dimmed" ta="center" py="lg">{readOnly ? t('common.empty') : t('inbounds.emptyHint')}</Text></Table.Td></Table.Tr>}
          </Table.Tbody>
        </Table>
      </Card>
      <Modal opened={editing !== null} onClose={() => setEditing(null)} title={editing === 'new' ? t('inbounds.create') : t('common.edit')} size="xl">
        {editing !== null && <InboundForm initial={toValues(editing === 'new' ? undefined : editing)} busy={save.isPending} onSubmit={(b) => save.mutate(b)} onCancel={() => setEditing(null)} />}
      </Modal>
    </>
  )
}
