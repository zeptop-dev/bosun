import { Badge, Button, Card, Group, Table, Text } from '@mantine/core'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconRefresh } from '@tabler/icons-react'
import { useTranslation } from 'react-i18next'
import { api, type DoctorReport, type Status } from '../lib/api'
import { bytes, when } from '../lib/format'
import { toast } from '../lib/notify'
import { PageHeader } from '../components/PageHeader'

const colour: Record<string, string> = { ok: 'teal', warn: 'orange', fail: 'red', skip: 'gray' }

// Read-only diagnostics of this node: cores, listeners, certificates,
// forwards, firewall, disk, panel link. Runs on open and on demand.
export default function DoctorPage() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['doctor'], queryFn: () => api.get<DoctorReport>('/api/doctor'), staleTime: 30_000 })
  const rerun = useMutation({ mutationFn: () => api.get<DoctorReport>('/api/doctor?fresh=1'), onSuccess: (r) => qc.setQueryData(['doctor'], r), onError: toast.err })
  const status = useQuery({ queryKey: ['status'], queryFn: () => api.get<Status>('/api/status'), refetchInterval: 5_000 })
  const delivery = status.data?.agent?.panel === 'captain' ? status.data.agent.delivery : undefined
  const r = q.data
  const sum = r?.summary
  return (
    <>
      <PageHeader title={t('doctor.title')} subtitle={t('doctor.subtitle')} actions={<Button leftSection={<IconRefresh size={16} />} loading={rerun.isPending || q.isFetching} onClick={() => rerun.mutate()}>{t('doctor.run')}</Button>} />
      {delivery && <Card mb="lg">
        <Text fw={600} mb="xs">{t('delivery.title')}</Text>
        <Text size="sm" c="dimmed" mb="sm">{t('delivery.hint')}</Text>
        <Table><Table.Tbody>
          <Table.Tr><Table.Td>{t('delivery.pending')}</Table.Td><Table.Td>{bytes(delivery.pending_bytes)}</Table.Td></Table.Tr>
          <Table.Tr><Table.Td>{t('delivery.buffered')}</Table.Td><Table.Td>{bytes(delivery.buffered_bytes)}</Table.Td></Table.Tr>
          <Table.Tr><Table.Td>{t('delivery.oldest')}</Table.Td><Table.Td>{delivery.oldest_at ? when(delivery.oldest_at) : '—'}</Table.Td></Table.Tr>
          <Table.Tr><Table.Td>{t('delivery.storage')}</Table.Td><Table.Td>{bytes(delivery.journal_bytes)}</Table.Td></Table.Tr>
        </Table.Tbody></Table>
      </Card>}
      <Card p={0}>
        <Group p="sm" gap="xs" justify="space-between">
          <Group gap="xs">
            <Badge color="teal" variant="light">{t('doctor.ok')} {sum?.ok ?? 0}</Badge>
            <Badge color="orange" variant="light">{t('doctor.warn')} {sum?.warn ?? 0}</Badge>
            <Badge color="red" variant="light">{t('doctor.fail')} {sum?.fail ?? 0}</Badge>
            <Badge color="gray" variant="light">{t('doctor.skip')} {sum?.skip ?? 0}</Badge>
          </Group>
          {r?.at && <Text size="xs" c="dimmed">{t('doctor.ranAt', { at: when(r.at) })}</Text>}
        </Group>
        <Table>
          <Table.Thead><Table.Tr><Table.Th w={110}>{t('doctor.status')}</Table.Th><Table.Th>{t('doctor.check')}</Table.Th><Table.Th>{t('doctor.detail')}</Table.Th></Table.Tr></Table.Thead>
          <Table.Tbody>
            {(r?.checks ?? []).map((c) => (
              <Table.Tr key={c.id}>
                <Table.Td><Badge color={colour[c.status] ?? 'gray'} variant={c.status === 'skip' ? 'outline' : 'filled'}>{t(`doctor.${c.status}`)}</Badge></Table.Td>
                <Table.Td><Text size="sm" fw={600}>{c.name}</Text><Text size="xs" c="dimmed" ff="monospace">{c.id}</Text></Table.Td>
                <Table.Td><Text size="sm" c={c.status === 'fail' ? 'red' : c.status === 'warn' ? 'orange' : undefined}>{c.detail || '—'}</Text></Table.Td>
              </Table.Tr>
            ))}
            {!q.isLoading && (r?.checks ?? []).length === 0 && <Table.Tr><Table.Td colSpan={3}><Text c="dimmed" ta="center" py="lg">{t('doctor.empty')}</Text></Table.Td></Table.Tr>}
          </Table.Tbody>
        </Table>
      </Card>
    </>
  )
}
