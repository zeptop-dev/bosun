import { Badge, Button, Card, Group, NumberInput, PasswordInput, Stack, Switch, Text, TextInput, Title } from '@mantine/core'
import { useForm } from '@mantine/form'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import { when } from '../lib/format'
import { toast } from '../lib/notify'

interface KomariSettings { enabled: boolean; server: string; key: string; name: string; interval: number }
interface KomariStatus { enabled: boolean; server: string; uuid: string; registered: boolean; last_report: string; last_error: string; reports: number }
interface KomariInfo { settings: KomariSettings; has_key: boolean; status: KomariStatus | null }

// Report this node to a Komari server as an agent (auto-discovery key,
// then metrics + ping tasks). Independent of bosun's own probe.
export function KomariCard({ readOnly }: { readOnly?: boolean }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['komari'], queryFn: () => api.get<KomariInfo>('/api/komari'), refetchInterval: 10_000 })
  const form = useForm<KomariSettings>({ initialValues: { enabled: false, server: '', key: '', name: '', interval: 3 } })
  useEffect(() => { if (q.data) form.setValues({ ...q.data.settings, key: '', interval: q.data.settings.interval || 3 }) }, [q.data]) // eslint-disable-line react-hooks/exhaustive-deps
  const save = useMutation({ mutationFn: (v: KomariSettings) => api.put('/api/komari', v), onSuccess: () => { toast.ok(t('common.saved')); form.setFieldValue('key', ''); qc.invalidateQueries({ queryKey: ['komari'] }) }, onError: toast.err })
  const st = q.data?.status
  return (
    <Card mb="lg">
      <Group justify="space-between" mb="xs">
        <Title order={5}>{t('komari.title')}</Title>
        {st && st.enabled && (st.last_error ? <Badge color="red" variant="light">{t('komari.error')}</Badge> : st.registered ? <Badge color="teal" variant="light">{t('komari.reporting')}</Badge> : <Badge color="yellow" variant="light">{t('komari.registering')}</Badge>)}
      </Group>
      <Text size="xs" c="dimmed" mb="sm">{t('komari.hint')}</Text>
      <form onSubmit={form.onSubmit((v) => save.mutate(v))}><Stack gap="sm">
        <Group grow align="flex-end">
          <TextInput label={t('komari.server')} placeholder="https://komari.example.com" disabled={readOnly} {...form.getInputProps('server')} />
          <PasswordInput label={t('komari.key')} description={q.data?.has_key ? t('komari.keySet') : t('komari.keyHint')} placeholder={q.data?.has_key ? '••••••••' : ''} disabled={readOnly} {...form.getInputProps('key')} />
        </Group>
        <Group grow align="flex-end">
          <TextInput label={t('komari.name')} description={t('komari.nameHint')} disabled={readOnly} {...form.getInputProps('name')} />
          <NumberInput label={t('komari.interval')} min={1} max={300} disabled={readOnly} {...form.getInputProps('interval')} />
          <Switch label={t('komari.enabled')} mb={6} disabled={readOnly} {...form.getInputProps('enabled', { type: 'checkbox' })} />
        </Group>
        {st && st.enabled && (
          <Text size="xs" c={st.last_error ? 'red' : 'dimmed'}>
            {st.uuid ? `${t('komari.uuid')} ${st.uuid} · ` : ''}{st.reports > 0 ? t('komari.lastReport', { at: when(st.last_report), n: st.reports }) : t('komari.noReport')}{st.last_error ? ` · ${st.last_error}` : ''}
          </Text>
        )}
        {!readOnly && <Group justify="flex-end"><Button type="submit" size="xs" loading={save.isPending}>{t('common.save')}</Button></Group>}
      </Stack></form>
    </Card>
  )
}
