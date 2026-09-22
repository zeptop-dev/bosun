import { Badge, Button, Card, Group, NumberInput, PasswordInput, SegmentedControl, Stack, Switch, Text, TextInput, Title } from '@mantine/core'
import { useForm } from '@mantine/form'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import { when } from '../lib/format'
import { toast } from '../lib/notify'

interface DStatusSettings { enabled: boolean; mode: string; listen: string; key: string; server: string; sid: string; interval: number }
interface DStatusStatus { enabled: boolean; mode: string; listen: string; server: string; last_error: string; last_scrape: string; denied: number; last_report: string; reports: number }
interface DStatusInfo { settings: DStatusSettings; has_key: boolean; status: DStatusStatus | null }

// Stand in for DStatus' own agent: passive = serve GET /stat for the panel
// to scrape, active = post the sample to the panel instead (no open port).
export function DStatusCard({ readOnly }: { readOnly?: boolean }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['dstatus'], queryFn: () => api.get<DStatusInfo>('/api/dstatus'), refetchInterval: 10_000 })
  const form = useForm<DStatusSettings>({ initialValues: { enabled: false, mode: 'passive', listen: '', key: '', server: '', sid: '', interval: 3 } })
  useEffect(() => { if (q.data) form.setValues({ ...q.data.settings, mode: q.data.settings.mode || 'passive', key: '', interval: q.data.settings.interval || 3 }) }, [q.data]) // eslint-disable-line react-hooks/exhaustive-deps
  const save = useMutation({ mutationFn: (v: DStatusSettings) => api.put('/api/dstatus', v), onSuccess: () => { toast.ok(t('common.saved')); form.setFieldValue('key', ''); qc.invalidateQueries({ queryKey: ['dstatus'] }) }, onError: toast.err })
  const st = q.data?.status
  const active = form.values.mode === 'active'
  const badge = st && st.enabled && (st.last_error && !(st.mode === 'active' && st.reports > 0)
    ? <Badge color="red" variant="light">{t('dstatus.error')}</Badge>
    : st.mode === 'active'
      ? (st.reports > 0 ? <Badge color="teal" variant="light">{t('dstatus.reporting')}</Badge> : <Badge color="yellow" variant="light">{t('dstatus.waiting')}</Badge>)
      : (st.last_scrape ? <Badge color="teal" variant="light">{t('dstatus.scraped')}</Badge> : <Badge color="yellow" variant="light">{t('dstatus.listening')}</Badge>))
  return (
    <Card mb="lg">
      <Group justify="space-between" mb="xs">
        <Title order={5}>{t('dstatus.title')}</Title>
        {badge}
      </Group>
      <Text size="xs" c="dimmed" mb="sm">{t('dstatus.hint')}</Text>
      <form onSubmit={form.onSubmit((v) => save.mutate(v))}><Stack gap="sm">
        <Group align="flex-start">
          <SegmentedControl size="xs" disabled={readOnly} data={[{ value: 'passive', label: t('dstatus.passive') }, { value: 'active', label: t('dstatus.active') }]} {...form.getInputProps('mode')} />
          <Text size="xs" c="dimmed" mt={4}>{active ? t('dstatus.activeHint') : t('dstatus.passiveHint')}</Text>
        </Group>
        <Group grow align="flex-start">
          {active
            ? <TextInput label={t('dstatus.server')} description={t('dstatus.serverHint')} placeholder="https://status.example.com" disabled={readOnly} {...form.getInputProps('server')} />
            : <TextInput label={t('dstatus.listen')} description={t('dstatus.listenHint')} placeholder=":9999" disabled={readOnly} {...form.getInputProps('listen')} />}
          <PasswordInput label={t('dstatus.key')} description={q.data?.has_key ? t('dstatus.keySet') : t('dstatus.keyHint')} placeholder={q.data?.has_key ? '••••••••' : ''} disabled={readOnly} {...form.getInputProps('key')} />
        </Group>
        {active && (
          <Group grow align="flex-start">
            <TextInput label={t('dstatus.sid')} description={t('dstatus.sidHint')} disabled={readOnly} {...form.getInputProps('sid')} />
            <NumberInput label={t('dstatus.interval')} min={1} max={300} disabled={readOnly} {...form.getInputProps('interval')} />
          </Group>
        )}
        <Group justify="space-between" align="flex-start">
          <Switch label={t('dstatus.enabled')} disabled={readOnly} {...form.getInputProps('enabled', { type: 'checkbox' })} />
          {!readOnly && <Button type="submit" size="xs" loading={save.isPending}>{t('common.save')}</Button>}
        </Group>
        {st && st.enabled && (
          <Text size="xs" c={st.last_error && !(st.mode === 'active' && st.reports > 0) ? 'red' : 'dimmed'}>
            {st.mode === 'active'
              ? (st.reports > 0 ? t('dstatus.lastReport', { at: when(st.last_report), n: st.reports }) : t('dstatus.noReport'))
              : (st.last_scrape ? t('dstatus.lastScrape', { at: when(st.last_scrape) }) : t('dstatus.noScrape', { listen: st.listen }))}
            {st.denied > 0 ? ` · ${t('dstatus.denied', { n: st.denied })}` : ''}{st.last_error ? ` · ${st.last_error}` : ''}
          </Text>
        )}
      </Stack></form>
    </Card>
  )
}
