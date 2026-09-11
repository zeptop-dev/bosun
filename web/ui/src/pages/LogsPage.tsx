import { Badge, Card, Group, ScrollArea, Switch, Table, Text } from '@mantine/core'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, type LogEntry } from '../lib/api'
import { PageHeader } from '../components/PageHeader'

const colors: Record<string, string> = { DEBUG: 'gray', INFO: 'blue', WARN: 'yellow', ERROR: 'red' }

export default function LogsPage() {
  const { t } = useTranslation()
  const [live, setLive] = useState(true)
  const q = useQuery({ queryKey: ['logs'], queryFn: () => api.get<LogEntry[]>('/api/logs?n=300'), refetchInterval: live ? 3_000 : false })
  return (
    <>
      <PageHeader title={t('logs.title')} subtitle={t('logs.subtitle')} actions={<Switch label={t('logs.live')} checked={live} onChange={(e) => setLive(e.currentTarget.checked)} />} />
      <Card p={0}>
        <ScrollArea h="calc(100vh - 200px)">
          <Table fz="xs" verticalSpacing={4}>
            <Table.Tbody>
              {[...(q.data ?? [])].reverse().map((e, i) => (
                <Table.Tr key={i}>
                  <Table.Td w={150}><Text size="xs" c="dimmed" ff="monospace">{new Date(e.time).toLocaleTimeString()}</Text></Table.Td>
                  <Table.Td w={70}><Badge size="xs" color={colors[e.level] ?? 'gray'}>{e.level}</Badge></Table.Td>
                  <Table.Td><Group gap={6}><Text size="xs">{e.msg}</Text>{e.attrs && <Text size="xs" c="dimmed" ff="monospace">{e.attrs}</Text>}</Group></Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </ScrollArea>
      </Card>
    </>
  )
}
