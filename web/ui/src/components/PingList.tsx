import { Badge, Group, Text, Tooltip } from '@mantine/core'
import { useTranslation } from 'react-i18next'
import type { Ping } from '../lib/api'

const ms = (v: number) => (v < 0 ? '×' : `${Math.round(v)} ms`)
const colour = (p: Ping) => (p.latency_ms < 0 ? 'red' : p.latency_ms > 200 ? 'orange' : 'teal')

// Latency results grouped the way the probe produces them: carrier points
// (task 0), line RTT (negative ids, one per ingress) and configured tasks.
export function PingList({ pings }: { pings: Ping[] }) {
  const { t } = useTranslation()
  const groups: { key: string; items: Ping[] }[] = [
    { key: 'carriers', items: pings.filter((p) => p.task_id === 0) },
    { key: 'lines', items: pings.filter((p) => p.task_id < 0) },
    { key: 'tasks', items: pings.filter((p) => p.task_id > 0) },
  ].filter((g) => g.items.length > 0)
  if (groups.length === 0) return <Text size="sm" c="dimmed">{t('probe.noResults')}</Text>
  return (
    <>
      {groups.map((g) => (
        <Group key={g.key} gap="xs" mb={6} wrap="wrap">
          <Text size="xs" c="dimmed" w={72}>{t(`probe.group.${g.key}`)}</Text>
          {g.items.map((p) => (
            <Tooltip key={`${p.task_id}-${p.name}`} label={[p.loss !== undefined ? t('probe.loss', { pct: p.loss.toFixed(0) }) : '', p.at ? new Date(p.at * 1000).toLocaleTimeString() : ''].filter(Boolean).join(' · ') || p.name}>
              <Badge variant="light" color={colour(p)} size="md" style={{ textTransform: 'none' }}>{p.name} {p.mbps ? `${p.mbps.toFixed(1)} Mbps` : ms(p.latency_ms)}</Badge>
            </Tooltip>
          ))}
        </Group>
      ))}
    </>
  )
}
