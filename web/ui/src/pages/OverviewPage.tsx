import { Alert, Badge, Card, Group, Progress, SimpleGrid, Skeleton, Stack, Table, Text } from '@mantine/core'
import { AreaChart } from '@mantine/charts'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { IconAlertTriangle, IconDevices, IconPlugConnected, IconArrowsExchange, IconClock } from '@tabler/icons-react'
import { api, type Status } from '../lib/api'
import { ago, bytes } from '../lib/format'
import { PageHeader } from '../components/PageHeader'
import { PingList } from '../components/PingList'
import { Stat } from '../components/Stat'

function uptime(s: number) {
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60)
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`
}

export default function OverviewPage() {
  const { t } = useTranslation()
  const q = useQuery({ queryKey: ['status'], queryFn: () => api.get<Status>('/api/status'), refetchInterval: 5_000 })
  const s = q.data
  const host = s?.host
  const pct = (used?: number, total?: number) => (used && total ? Math.round((used / total) * 100) : 0)
  const series = (s?.history ?? []).map((d) => ({ day: new Date(d.day * 1000).toLocaleDateString(undefined, { month: 'numeric', day: 'numeric' }), GiB: +((d.up + d.down) / 2 ** 30).toFixed(3) }))
  const cores = Object.entries(s?.agent?.core_running ?? {})
  return (
    <>
      <PageHeader title={t('overview.title')} subtitle={s ? t('overview.subtitle', { mode: t(`mode.${s.mode}`), panel: s.agent?.panel ?? '-' }) : undefined} />
      {s?.agent?.last_error && <Alert color="red" icon={<IconAlertTriangle size={16} />} mb="lg" title={t('overview.applyError')}>{s.agent.last_error}</Alert>}
      {s?.mode === 'managed' && <Alert color="orange" mb="lg" title={t('mode.managed')}>{t('mode.managedHint')} {s.managed?.url}</Alert>}
      {!s ? <Skeleton h={120} /> : (
        <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }} mb="lg">
          <Stat label={t('overview.onlineUsers')} value={s.online_users} hint={t('overview.ofUsers', { count: s.users })} icon={<IconDevices size={18} opacity={0.6} />} />
          <Stat label={t('overview.inbounds')} value={s.inbounds} hint={s.agent ? t('overview.applied', { count: s.agent.inbounds }) : undefined} icon={<IconPlugConnected size={18} opacity={0.6} />} />
          <Stat label={t('overview.traffic')} value={bytes(s.total_up + s.total_down)} hint={`↑ ${bytes(s.total_up)} · ↓ ${bytes(s.total_down)}`} icon={<IconArrowsExchange size={18} opacity={0.6} />} />
          <Stat label={t('overview.uptime')} value={uptime(s.uptime_seconds)} hint={s.last_report ? t('overview.lastReport', { ago: ago(s.last_report) }) : undefined} icon={<IconClock size={18} opacity={0.6} />} />
        </SimpleGrid>
      )}
      <SimpleGrid cols={{ base: 1, md: 2 }} mb="lg">
        <Card>
          <Text size="xs" tt="uppercase" c="dimmed" fw={600} mb="xs">{t('overview.host')}</Text>
          {host && host.mem_total ? (
            <Stack gap="xs">
              <div><Group justify="space-between"><Text size="sm">CPU</Text><Text size="sm">{Math.round(host.cpu_percent ?? 0)}%</Text></Group><Progress value={host.cpu_percent ?? 0} size="sm" /></div>
              <div><Group justify="space-between"><Text size="sm">{t('overview.memory')}</Text><Text size="sm">{bytes(host.mem_used ?? 0)} / {bytes(host.mem_total)}</Text></Group><Progress value={pct(host.mem_used, host.mem_total)} size="sm" color="grape" /></div>
              <div><Group justify="space-between"><Text size="sm">{t('overview.disk')}</Text><Text size="sm">{bytes(host.disk_used ?? 0)} / {bytes(host.disk_total ?? 0)}</Text></Group><Progress value={pct(host.disk_used, host.disk_total)} size="sm" color="orange" /></div>
            </Stack>
          ) : <Text size="sm" c="dimmed">—</Text>}
        </Card>
        <Card>
          <Text size="xs" tt="uppercase" c="dimmed" fw={600} mb="xs">{t('overview.cores')}</Text>
          <Table>
            <Table.Tbody>
              {cores.map(([name, running]) => (
                <Table.Tr key={name}>
                  <Table.Td><Text size="sm" fw={600}>{name}</Text></Table.Td>
                  <Table.Td><Badge color={running ? 'teal' : 'gray'}>{running ? t('overview.running') : t('overview.stopped')}</Badge></Table.Td>
                  <Table.Td><Text size="sm" c="dimmed">{t('overview.inboundsOn', { count: s?.agent?.core_inbounds?.[name] ?? 0 })}</Text></Table.Td>
                </Table.Tr>
              ))}
              {cores.length === 0 && <Table.Tr><Table.Td><Text size="sm" c="dimmed">{t('common.empty')}</Text></Table.Td></Table.Tr>}
            </Table.Tbody>
          </Table>
        </Card>
      </SimpleGrid>
      {(s?.pings?.length ?? 0) > 0 && (
        <Card mb="lg">
          <Text size="xs" tt="uppercase" c="dimmed" fw={600} mb="xs">{t('overview.latency')}</Text>
          <PingList pings={s!.pings!} />
        </Card>
      )}
      <Card>
        <Text fw={600}>{t('overview.chart')}</Text>
        <Text size="xs" c="dimmed" mb="md">{t('overview.chartSub')}</Text>
        <AreaChart h={200} data={series} dataKey="day" series={[{ name: 'GiB', color: 'cyan.5' }]} curveType="monotone" withDots={false} gridAxis="x" />
      </Card>
    </>
  )
}
