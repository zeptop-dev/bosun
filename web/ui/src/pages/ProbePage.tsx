import { ActionIcon, Button, Card, Group, NumberInput, Select, Stack, Switch, Table, Text, TextInput, Textarea, Title } from '@mantine/core'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconPlus, IconTrash } from '@tabler/icons-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { DStatusCard } from '../components/DStatusCard'
import { KomariCard } from '../components/KomariCard'
import { api, type Carrier, type ProbeInfo, type ProbeSettings, type ProbeTask } from '../lib/api'
import { useAuth } from '../lib/auth'
import { toast } from '../lib/notify'
import { PageHeader } from '../components/PageHeader'
import { PingList } from '../components/PingList'

const parseCarriers = (text: string): Carrier[] => text.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => { const [name, ...rest] = l.split(/[\s,=]+/); return { name, addr: rest.join('') } })
const carriersText = (c: Carrier[]) => c.map((x) => `${x.name} ${x.addr}`).join('\n')
const emptySettings: ProbeSettings = { enabled: false, carrier_ping: true, carriers: [], tasks: [] }

// Latency probing on this node: carrier points, custom tasks and line RTT.
// Standalone nodes keep the settings here; under Captain the panel decides.
export default function ProbePage() {
  const { t } = useTranslation()
  const { me } = useAuth()
  const qc = useQueryClient()
  const readOnly = me?.mode !== 'local' || !!me?.fixed
  const q = useQuery({ queryKey: ['probe'], queryFn: () => api.get<ProbeInfo>('/api/probe'), refetchInterval: 10_000 })
  const [s, setS] = useState<ProbeSettings>(emptySettings)
  const [carriers, setCarriers] = useState('')
  const [loaded, setLoaded] = useState(false)
  useEffect(() => {
    // Only the first load seeds the form; later refetches must not clobber edits.
    if (q.data && !loaded) { setS({ ...emptySettings, ...q.data.settings, carriers: q.data.settings.carriers ?? [], tasks: q.data.settings.tasks ?? [] }); setCarriers(carriersText(q.data.settings.carriers ?? [])); setLoaded(true) }
  }, [q.data, loaded])
  const save = useMutation({ mutationFn: (v: ProbeSettings) => api.put('/api/probe', { ...v, carriers: parseCarriers(carriers) }), onSuccess: () => { toast.ok(t('common.saved')); qc.invalidateQueries({ queryKey: ['probe'] }); qc.invalidateQueries({ queryKey: ['status'] }) }, onError: toast.err })
  const setTask = (i: number, patch: Partial<ProbeTask>) => setS((cur) => ({ ...cur, tasks: cur.tasks.map((x, j) => (j === i ? { ...x, ...patch } : x)) }))
  const addTask = () => setS((cur) => ({ ...cur, tasks: [...cur.tasks, { id: Math.max(0, ...cur.tasks.map((x) => x.id)) + 1, name: '', type: 'tcp', target: '', interval_seconds: 30, source_ip: '' }] }))
  const defaults = (q.data?.defaults ?? []).map((c) => `${c.name} ${c.addr}`).join('\n')
  return (
    <>
      <PageHeader title={t('probe.title')} subtitle={t('probe.subtitle')} />
      <Card mb="lg">
        <Title order={5} mb={4}>{t('probe.results')}</Title>
        <Text size="xs" c="dimmed" mb="sm">{t('probe.resultsHint')}</Text>
        <PingList pings={q.data?.results ?? []} />
      </Card>
      <Card>
        <Title order={5} mb="xs">{t('probe.settings')}</Title>
        {readOnly && <Text size="xs" c="orange" mb="sm">{t('probe.managedHint')}</Text>}
        <Stack gap="sm">
          <Group grow align="flex-end">
            <Switch label={t('probe.enabled')} description={t('probe.enabledHint')} disabled={readOnly} checked={s.enabled} onChange={(e) => setS({ ...s, enabled: e.currentTarget.checked })} />
            <Switch label={t('probe.carrier')} description={t('probe.carrierHint')} disabled={readOnly} checked={s.carrier_ping} onChange={(e) => setS({ ...s, carrier_ping: e.currentTarget.checked })} />
          </Group>
          {s.carrier_ping && <Textarea label={t('probe.carriers')} description={t('probe.carriersHint')} autosize minRows={2} placeholder={defaults} disabled={readOnly} styles={{ input: { fontFamily: 'monospace', fontSize: 12 } }} value={carriers} onChange={(e) => setCarriers(e.currentTarget.value)} />}
          <Text size="sm" fw={600} mt="xs">{t('probe.tasks')}</Text>
          <Text size="xs" c="dimmed">{t('probe.tasksHint')}</Text>
          {s.tasks.length > 0 && (
            <Table fz="sm">
              <Table.Thead><Table.Tr><Table.Th>{t('probe.taskName')}</Table.Th><Table.Th>{t('probe.taskType')}</Table.Th><Table.Th>{t('probe.taskTarget')}</Table.Th><Table.Th>{t('probe.taskInterval')}</Table.Th><Table.Th>{t('probe.taskSource')}</Table.Th><Table.Th /></Table.Tr></Table.Thead>
              <Table.Tbody>
                {s.tasks.map((task, i) => (
                  <Table.Tr key={task.id}>
                    <Table.Td><TextInput size="xs" disabled={readOnly} value={task.name} onChange={(e) => setTask(i, { name: e.currentTarget.value })} /></Table.Td>
                    <Table.Td><Select size="xs" w={110} disabled={readOnly} data={['icmp', 'tcp', 'http', 'download']} allowDeselect={false} value={task.type} onChange={(v) => setTask(i, { type: v ?? 'tcp' })} /></Table.Td>
                    <Table.Td><TextInput size="xs" disabled={readOnly} placeholder={task.type === 'download' ? 'https://speed.cloudflare.com/__down?bytes=100000000' : task.type === 'tcp' ? '1.1.1.1:443' : '1.1.1.1'} value={task.target} onChange={(e) => setTask(i, { target: e.currentTarget.value })} /></Table.Td>
                    <Table.Td><NumberInput size="xs" w={90} min={5} disabled={readOnly} value={task.interval_seconds} onChange={(v) => setTask(i, { interval_seconds: Number(v) || 30 })} /></Table.Td>
                    <Table.Td><TextInput size="xs" w={130} disabled={readOnly} placeholder="10.10.0.2" value={task.source_ip} onChange={(e) => setTask(i, { source_ip: e.currentTarget.value })} /></Table.Td>
                    <Table.Td>{!readOnly && <ActionIcon variant="subtle" color="red" size="sm" onClick={() => setS((cur) => ({ ...cur, tasks: cur.tasks.filter((_, j) => j !== i) }))}><IconTrash size={14} /></ActionIcon>}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          )}
          {!readOnly && (
            <Group justify="space-between">
              <Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={addTask}>{t('probe.addTask')}</Button>
              <Button size="xs" loading={save.isPending} onClick={() => save.mutate(s)}>{t('common.save')}</Button>
            </Group>
          )}
        </Stack>
      </Card>
      <KomariCard readOnly={readOnly} />
      <DStatusCard readOnly={readOnly} />
    </>
  )
}
