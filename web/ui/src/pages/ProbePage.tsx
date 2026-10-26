import { ResourceOptionsFields } from '../components/ResourceOptionsFields'
import { ActionIcon, Button, Card, Group, NumberInput, Select, Stack, Switch, Table, Text, TextInput, Textarea, Title } from '@mantine/core'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconPlus, IconTrash } from '@tabler/icons-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, type Carrier, type CarrierProbeConfig, type ProbeInfo, type ProbeSettings, type ProbeTask } from '../lib/api'
import { useAuth } from '../lib/auth'
import { toast } from '../lib/notify'
import { PageHeader } from '../components/PageHeader'
import { NetworkQualityTable } from '../components/NetworkQualityTable'
import { NetworkDiagnosticsCard } from '../components/NetworkDiagnosticsCard'

const parseCarriers = (text: string): Carrier[] => text.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => { const [name, ...rest] = l.split(/[\s,=]+/); return { name, addr: rest.join('') } })
const carriersText = (c: Carrier[]) => c.map((x) => `${x.name} ${x.addr}`).join('\n')
type TargetKey = 'tcp_ipv4' | 'tcp_ipv6' | 'icmp_ipv4' | 'icmp_ipv6'
const targetKeys: TargetKey[] = ['tcp_ipv4', 'tcp_ipv6', 'icmp_ipv4', 'icmp_ipv6']
const emptyTargets = { tcp_ipv4: '', tcp_ipv6: '', icmp_ipv4: '', icmp_ipv6: '' }
const defaultTargets = (protocol: string, family: string) => [['CT','4134'],['CU','4837'],['CM','9808']].map(([name, asn]) => `${name} ${family}.pek-${asn}.endpoint.nxtrace.org${protocol === 'tcp' ? ':80' : ''}`).join('\n')
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
  const [targets, setTargets] = useState(emptyTargets)
  const [loaded, setLoaded] = useState(false)
  useEffect(() => {
    // Only the first load seeds the form; later refetches must not clobber edits.
    if (q.data && !loaded) {
      const settings = q.data.settings
      const carrier_probe: CarrierProbeConfig = settings.carrier_probe ?? { protocol: 'tcp', family: 'ipv4', tcp_ipv4: settings.carriers ?? [] }
      setS({ ...emptySettings, ...settings, carrier_probe, carriers: settings.carriers ?? [], tasks: settings.tasks ?? [] })
      setTargets(Object.fromEntries(targetKeys.map((key) => [key, carriersText(carrier_probe[key] ?? [])])) as typeof emptyTargets)
      setLoaded(true)
    }
  }, [q.data, loaded])
  const save = useMutation({ mutationFn: (v: ProbeSettings) => api.put('/api/probe', { ...v, carrier_probe: { ...v.carrier_probe, ...Object.fromEntries(targetKeys.map((key) => [key, parseCarriers(targets[key])])) } }), onSuccess: () => { toast.ok(t('common.saved')); qc.invalidateQueries({ queryKey: ['probe'] }); qc.invalidateQueries({ queryKey: ['status'] }) }, onError: toast.err })
  const setTask = (i: number, patch: Partial<ProbeTask>) => setS((cur) => ({ ...cur, tasks: cur.tasks.map((x, j) => (j === i ? { ...x, ...patch } : x)) }))
  const addTask = () => setS((cur) => ({ ...cur, tasks: [...cur.tasks, { id: Math.max(0, ...cur.tasks.map((x) => x.id)) + 1, name: '', type: 'tcp', target: '', interval_seconds: 30, source_ip: '' }] }))
  const mode = s.carrier_probe ?? { protocol: 'tcp', family: 'ipv4' }
  const setMode = (patch: Partial<CarrierProbeConfig>) => setS((cur) => ({ ...cur, carrier_probe: { ...mode, ...patch } }))
  const families = mode.family === 'dual' ? ['ipv4', 'ipv6'] : [mode.family]
  return (
    <>
      <PageHeader title={t('probe.title')} subtitle={t('probe.subtitle')} />
      {!readOnly && <NetworkDiagnosticsCard />}
      <Card mb="lg">
        <Title order={5} mb={4}>{t('probe.results')}</Title>
        <Text size="xs" c="dimmed" mb="sm">{t('probe.resultsHint')}</Text>
        <NetworkQualityTable samples={q.data?.results ?? []} />
      </Card>
      <Card>
        <Title order={5} mb="xs">{t('probe.settings')}</Title>
        {readOnly && <Text size="xs" c="orange" mb="sm">{t('probe.managedHint')}</Text>}
        <Stack gap="sm">
          <ResourceOptionsFields value={s.resources} onChange={(v) => setS((cur) => ({ ...cur, resources: v }))} disabled={readOnly} />
          <Group grow align="flex-end">
            <Switch label={t('probe.enabled')} description={t('probe.enabledHint')} disabled={readOnly} checked={s.enabled} onChange={(e) => setS({ ...s, enabled: e.currentTarget.checked })} />
            <Switch label={t('probe.carrier')} description={t('probe.carrierHint')} disabled={readOnly} checked={s.carrier_ping} onChange={(e) => setS({ ...s, carrier_ping: e.currentTarget.checked })} />
          </Group>
          {s.carrier_ping && <>
            <Group grow>
              <Select label={t('probe.carrierProtocol')} disabled={readOnly} data={['TCP', 'ICMP'].map((label) => ({ value: label.toLowerCase(), label }))} value={mode.protocol} allowDeselect={false} onChange={(value) => setMode({ protocol: value as 'tcp' | 'icmp' })} />
              <Select label={t('probe.carrierFamily')} disabled={readOnly} data={[{ value: 'ipv4', label: 'IPv4' }, { value: 'ipv6', label: 'IPv6' }, { value: 'dual', label: 'IPv4 + IPv6' }]} value={mode.family} allowDeselect={false} onChange={(value) => setMode({ family: value as CarrierProbeConfig['family'] })} />
            </Group>
            {families.map((family) => {
              const key = `${mode.protocol}_${family}` as TargetKey
              return <Textarea key={key} label={`${t('probe.carriers')} · ${family === 'ipv6' ? 'IPv6' : 'IPv4'}`} description={t(mode.protocol === 'icmp' ? 'probe.carriersICMPHint' : 'probe.carriersTCPHint')} autosize minRows={3} placeholder={defaultTargets(mode.protocol, family)} disabled={readOnly} styles={{ input: { fontFamily: 'monospace', fontSize: 12 } }} value={targets[key]} onChange={(e) => setTargets({ ...targets, [key]: e.currentTarget.value })} />
            })}
          </>}
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
              <Button size="xs" disabled={!loaded} loading={save.isPending} onClick={() => save.mutate(s)}>{t('common.save')}</Button>
            </Group>
          )}
        </Stack>
      </Card>
    </>
  )
}
