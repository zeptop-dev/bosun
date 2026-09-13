import { ActionIcon, Badge, Button, Card, Code, Group, Modal, Stack, Table, Text, Tooltip } from '@mantine/core'
import { useForm } from '@mantine/form'
import { modals } from '@mantine/modals'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconPencil, IconPlus, IconTrash } from '@tabler/icons-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, type Inbound, type Ingress } from '../lib/api'
import { useAuth } from '../lib/auth'
import { toast } from '../lib/notify'
import { PageHeader } from '../components/PageHeader'
import { IngressFields, emptyIngress, ingressPayload, ingressValues, type IngressValues } from '../components/IngressFields'

// Line ingresses of this node (IPLC / dedicated NICs). Inbounds pick one;
// share links and relay forwards derive their addresses from it.
export default function IngressesPage() {
  const { t } = useTranslation()
  const { me } = useAuth()
  const qc = useQueryClient()
  const readOnly = me?.mode !== 'local' || !!me?.fixed
  const q = useQuery({ queryKey: ['ingresses'], queryFn: () => api.get<Ingress[]>('/api/ingresses') })
  const inbounds = useQuery({ queryKey: ['inbounds'], queryFn: () => api.get<Inbound[]>('/api/inbounds') })
  const [editing, setEditing] = useState<Ingress | 'new' | null>(null)
  const form = useForm<IngressValues>({ initialValues: emptyIngress, validate: { Name: (v) => (v.trim() ? null : t('form.required')) } })
  const invalidate = () => { qc.invalidateQueries({ queryKey: ['ingresses'] }); qc.invalidateQueries({ queryKey: ['inbounds'] }); qc.invalidateQueries({ queryKey: ['probe'] }) }
  const save = useMutation({ mutationFn: (v: IngressValues) => editing === 'new' ? api.post('/api/ingresses', ingressPayload(v)) : api.put(`/api/ingresses/${encodeURIComponent((editing as Ingress).id)}`, ingressPayload(v)), onSuccess: () => { toast.ok(t('common.saved')); setEditing(null); invalidate() }, onError: toast.err })
  const del = useMutation({ mutationFn: (id: string) => api.del(`/api/ingresses/${encodeURIComponent(id)}`), onSuccess: () => { toast.ok(t('common.deleted')); invalidate() }, onError: toast.err })
  const open = (g: Ingress | 'new') => { form.setValues(g === 'new' ? emptyIngress : ingressValues(g)); setEditing(g) }
  const uses = (id: string) => (inbounds.data ?? []).filter((ib) => ib.ingress_id === id).length
  return (
    <>
      <PageHeader title={t('ingress.title')} subtitle={t('ingress.hint')} actions={!readOnly && <Button leftSection={<IconPlus size={16} />} onClick={() => open('new')}>{t('ingress.add')}</Button>} />
      <Card p={0}>
        <Table>
          <Table.Thead><Table.Tr><Table.Th>{t('ingress.name')}</Table.Th><Table.Th>{t('ingress.bindIP')}</Table.Th><Table.Th>{t('ingress.lineIP')}</Table.Th><Table.Th>{t('ingress.entryHost')}</Table.Th><Table.Th>{t('ingress.ports')}</Table.Th><Table.Th>{t('ingress.inbounds')}</Table.Th><Table.Th /></Table.Tr></Table.Thead>
          <Table.Tbody>
            {(q.data ?? []).map((g) => (
              <Table.Tr key={g.id}>
                <Table.Td><Text fw={600} size="sm">{g.name}</Text></Table.Td>
                <Table.Td>{g.bind_ip ? <Code>{g.bind_ip}</Code> : <Text size="xs" c="dimmed">{t('ingress.anyAddr')}</Text>}</Table.Td>
                <Table.Td>{g.line_ip ? <Code>{g.line_ip}</Code> : '—'}</Table.Td>
                <Table.Td>{g.entry_host ? <><Code>{g.entry_host}</Code>{g.entry_domain && <Text size="xs" c="dimmed">{g.entry_domain}</Text>}</> : <Tooltip label={t('ingress.noEntryHint')} multiline w={320}><Badge size="xs" color="orange" variant="light">{t('ingress.noEntry')}</Badge></Tooltip>}</Table.Td>
                <Table.Td><Text size="xs">{g.port_from ? `${g.port_from}–${g.port_to}` : t('ingress.anyPort')}{g.port_offset ? ` (${g.port_offset > 0 ? '+' : ''}${g.port_offset})` : ''}</Text></Table.Td>
                <Table.Td><Text size="xs">{uses(g.id)}</Text></Table.Td>
                <Table.Td><Group gap={4} justify="flex-end" wrap="nowrap">
                  {!readOnly && <ActionIcon variant="subtle" color="gray" onClick={() => open(g)}><IconPencil size={16} /></ActionIcon>}
                  {!readOnly && <ActionIcon variant="subtle" color="red" onClick={() => modals.openConfirmModal({ title: t('common.delete'), children: <Text size="sm">{t('ingress.deleteHint')}</Text>, labels: { confirm: t('common.delete'), cancel: t('common.cancel') }, confirmProps: { color: 'red' }, onConfirm: () => del.mutate(g.id) })}><IconTrash size={16} /></ActionIcon>}
                </Group></Table.Td>
              </Table.Tr>
            ))}
            {(q.data ?? []).length === 0 && <Table.Tr><Table.Td colSpan={7}><Text c="dimmed" ta="center" py="lg">{t('ingress.empty')}</Text></Table.Td></Table.Tr>}
          </Table.Tbody>
        </Table>
      </Card>
      <Modal opened={editing !== null} onClose={() => setEditing(null)} title={editing === 'new' ? t('ingress.add') : t('common.edit')} size="lg">
        <form onSubmit={form.onSubmit((v) => save.mutate(v))}><Stack>
          <IngressFields form={form} />
          <Group justify="flex-end"><Button variant="default" onClick={() => setEditing(null)}>{t('common.cancel')}</Button><Button type="submit" loading={save.isPending}>{t('common.save')}</Button></Group>
        </Stack></form>
      </Modal>
    </>
  )
}
