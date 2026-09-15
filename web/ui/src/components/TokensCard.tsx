import { ActionIcon, Button, Card, Code, Group, Stack, Table, Text, TextInput, Title } from '@mantine/core'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconTrash } from '@tabler/icons-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import { when } from '../lib/format'
import { toast } from '../lib/notify'
import { Copy } from './Copy'

interface Token { id: number; name: string; created_at: string; last_used_at?: string | null }

// Bearer tokens for scripts against the standalone API; shown once.
export function TokensCard() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['api-tokens'], queryFn: () => api.get<Token[]>('/api/tokens') })
  const [name, setName] = useState('')
  const [fresh, setFresh] = useState<string | null>(null)
  const create = useMutation({ mutationFn: () => api.post<{ token: string }>('/api/tokens', { Name: name }), onSuccess: (r) => { setFresh(r.token); setName(''); qc.invalidateQueries({ queryKey: ['api-tokens'] }) }, onError: toast.err })
  const del = useMutation({ mutationFn: (id: number) => api.del(`/api/tokens/${id}`), onSuccess: () => qc.invalidateQueries({ queryKey: ['api-tokens'] }), onError: toast.err })
  const example = `curl -H "Authorization: Bearer ${fresh ?? '<token>'}" ${window.location.origin}/api/status`
  return (
    <Card>
      <Title order={5} mb="xs">{t('tokens.title')}</Title>
      <Text size="xs" c="dimmed" mb="sm">{t('tokens.hint')}</Text>
      <Group align="flex-end" mb="sm"><TextInput label={t('tokens.name')} placeholder="backup-script" value={name} onChange={(e) => setName(e.currentTarget.value)} style={{ flex: 1 }} /><Button size="xs" mb={2} loading={create.isPending} disabled={!name.trim()} onClick={() => create.mutate()}>{t('tokens.create')}</Button></Group>
      {fresh && (
        <Stack gap={4} mb="sm">
          <Text size="xs" c="orange">{t('tokens.showOnce')}</Text>
          <Group gap={4} wrap="nowrap"><Code style={{ flex: 1, wordBreak: 'break-all' }}>{fresh}</Code><Copy value={fresh} /></Group>
        </Stack>
      )}
      {(q.data ?? []).length > 0 && (
        <Table fz="sm"><Table.Tbody>
          {q.data!.map((tk) => <Table.Tr key={tk.id}><Table.Td><Text fw={600}>{tk.name}</Text></Table.Td><Table.Td><Text size="xs" c="dimmed">{t('tokens.created')} {when(tk.created_at)}</Text></Table.Td><Table.Td><Text size="xs" c="dimmed">{tk.last_used_at ? `${t('tokens.lastUsed')} ${when(tk.last_used_at)}` : t('tokens.neverUsed')}</Text></Table.Td><Table.Td><ActionIcon variant="subtle" color="red" onClick={() => del.mutate(tk.id)}><IconTrash size={16} /></ActionIcon></Table.Td></Table.Tr>)}
        </Table.Tbody></Table>
      )}
      <Text size="xs" c="dimmed" mt="sm">{t('tokens.example')}</Text>
      <Group gap={4} align="flex-start" wrap="nowrap" mt={4}><Code block style={{ flex: 1 }}>{example}</Code><Copy value={example} /></Group>
    </Card>
  )
}
