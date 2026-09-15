import { Alert, Badge, Button, Card, Group, PasswordInput, Select, SimpleGrid, Stack, Switch, Table, Text, TextInput, Title } from '@mantine/core'
import { useForm } from '@mantine/form'
import { modals } from '@mantine/modals'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, type CoreRelease, type Settings, type Status } from '../lib/api'
import { UpdateCard } from '../components/UpdateCard'
import { BackupCard } from '../components/BackupCard'
import { TwoFactorCard } from '../components/TwoFactorCard'
import { TokensCard } from '../components/TokensCard'
import { useAuth } from '../lib/auth'
import { when } from '../lib/format'
import { toast } from '../lib/notify'
import { PageHeader } from '../components/PageHeader'

export default function SettingsPage() {
  const { t } = useTranslation()
  const { me, refresh } = useAuth()
  const qc = useQueryClient()
  const settings = useQuery({ queryKey: ['settings'], queryFn: () => api.get<Settings>('/api/settings') })
  const status = useQuery({ queryKey: ['status'], queryFn: () => api.get<Status>('/api/status'), refetchInterval: 5_000 })
  const cores = useQuery({ queryKey: ['cores'], queryFn: () => api.get<CoreRelease[]>('/api/cores') })
  const sform = useForm<Settings>({ initialValues: { public_host: '', node_name: '', acme_email: '', cloudflare_token: '', panel_domain: '', panel_acme: 'http', decoy_enabled: false, decoy_domain: '', decoy_upstream: '', decoy_acme: 'http' } })
  useEffect(() => { if (settings.data) sform.setValues(settings.data) }, [settings.data]) // eslint-disable-line react-hooks/exhaustive-deps
  const saveSettings = useMutation({ mutationFn: (v: Settings) => api.put('/api/settings', v), onSuccess: () => { toast.ok(t('common.saved')); qc.invalidateQueries({ queryKey: ['settings'] }); qc.invalidateQueries({ queryKey: ['links'] }) }, onError: toast.err })
  const aform = useForm({ initialValues: { Username: me?.username ?? 'admin', Password: '', Confirm: '' }, validate: { Confirm: (v, all) => (v === all.Password ? null : t('settings.mismatch')) } })
  const saveAdmin = useMutation({ mutationFn: (v: { Username: string; Password: string }) => api.put('/api/admin', v), onSuccess: () => { toast.ok(t('common.saved')); aform.setValues({ Password: '', Confirm: '' }); refresh() }, onError: toast.err })
  const mform = useForm({ initialValues: { url: '', pair_code: '' } })
  const adopt = useMutation({ mutationFn: (v: { url: string; pair_code: string }) => api.post('/api/mode/adopt', v), onSuccess: () => { toast.ok(t('mode.adopted')); refresh(); qc.invalidateQueries() }, onError: toast.err })
  const [keep, setKeep] = useState(false)
  const detach = useMutation({ mutationFn: () => api.post('/api/mode/detach', { keep }), onSuccess: () => { toast.ok(t('mode.detached')); refresh(); qc.invalidateQueries() }, onError: toast.err })
  const s = status.data
  const fixed = !!me?.fixed
  return (
    <>
      <PageHeader title={t('settings.title')} subtitle={t('settings.subtitle')} />
      <SimpleGrid cols={{ base: 1, md: 2 }} mb="lg">
        <Card>
          <Title order={5} mb="xs">{t('settings.node')}</Title>
          <form onSubmit={sform.onSubmit((v) => saveSettings.mutate(v))}><Stack gap="sm">
            <TextInput label={t('settings.publicHost')} description={t('settings.publicHostHint')} placeholder="node.example.com" {...sform.getInputProps('public_host')} />
            <TextInput label={t('settings.nodeName')} description={t('settings.nodeNameHint')} placeholder="JP-1" {...sform.getInputProps('node_name')} />
            <Title order={6} mt="xs">{t('settings.certs')}</Title>
            <Text size="xs" c="dimmed">{t('settings.certsHint')}</Text>
            <TextInput label={t('settings.acmeEmail')} placeholder="you@example.com" {...sform.getInputProps('acme_email')} />
            <PasswordInput label={t('settings.cfToken')} description={t('settings.cfTokenHint')} {...sform.getInputProps('cloudflare_token')} />
            <Group grow align="flex-end">
              <TextInput label={t('settings.panelDomain')} description={t('settings.panelDomainHint')} placeholder="node.example.com" {...sform.getInputProps('panel_domain')} />
              <Select label={t('inbounds.acme')} data={[{ value: 'http', label: t('inbounds.acmeHttp') }, { value: 'dns', label: t('inbounds.acmeDns') }]} allowDeselect={false} {...sform.getInputProps('panel_acme')} />
            </Group>
            <Title order={6} mt="xs">{t('settings.decoy')}</Title>
            <Text size="xs" c="dimmed">{t('settings.decoyHint')}</Text>
            <Switch label={t('settings.decoyEnabled')} {...sform.getInputProps('decoy_enabled', { type: 'checkbox' })} />
            {sform.values.decoy_enabled && (
              <>
                <Group grow align="flex-start">
                  <TextInput label={t('settings.decoyDomain')} description={t('settings.decoyDomainHint')} placeholder="www.example.com" required {...sform.getInputProps('decoy_domain')} />
                  <Select label={t('inbounds.acme')} data={[{ value: 'http', label: t('inbounds.acmeHttp') }, { value: 'dns', label: t('inbounds.acmeDns') }]} allowDeselect={false} {...sform.getInputProps('decoy_acme')} />
                </Group>
                <TextInput label={t('settings.decoyUpstream')} description={t('settings.decoyUpstreamHint')} placeholder="http://127.0.0.1:8080" {...sform.getInputProps('decoy_upstream')} />
                {s?.agent?.decoy && <Text size="xs" c={s.agent.decoy.error ? 'red' : s.agent.decoy.cert_ready ? 'teal' : 'orange'}>{s.agent.decoy.error ? s.agent.decoy.error : s.agent.decoy.cert_ready ? t('settings.decoyReady', { port: s.agent.decoy.port }) : t('settings.decoyPending')}</Text>}
              </>
            )}
            <Group justify="flex-end"><Button type="submit" size="xs" loading={saveSettings.isPending}>{t('common.save')}</Button></Group>
          </Stack></form>
        </Card>
        <Card>
          <Title order={5} mb="xs">{t('settings.login')}</Title>
          <form onSubmit={aform.onSubmit((v) => saveAdmin.mutate({ Username: v.Username, Password: v.Password }))}><Stack gap="sm">
            <TextInput label={t('login.username')} required {...aform.getInputProps('Username')} />
            <Group grow>
              <PasswordInput label={t('settings.newPassword')} description={t('settings.newPasswordHint')} {...aform.getInputProps('Password')} />
              <PasswordInput label={t('settings.confirm')} {...aform.getInputProps('Confirm')} />
            </Group>
            <Group justify="flex-end"><Button type="submit" size="xs" loading={saveAdmin.isPending}>{t('common.save')}</Button></Group>
          </Stack></form>
        </Card>
      </SimpleGrid>

      <Card mb="lg">
        <Group justify="space-between" mb="xs">
          <Title order={5}>{t('mode.title')}</Title>
          {s && <Badge color={fixed ? 'grape' : s.mode === 'managed' ? 'orange' : 'teal'}>{fixed ? t('mode.fixed', { driver: me?.fixed }) : t(`mode.${s.mode}`)}</Badge>}
        </Group>
        {fixed && <Text size="sm" c="dimmed">{t('mode.fixedHint', { driver: me?.fixed })}</Text>}
        {!fixed && s?.mode === 'local' && (
          <Stack gap="sm">
            <Text size="sm" c="dimmed">{t('mode.adoptHint')}</Text>
            <form onSubmit={mform.onSubmit((v) => { modals.openConfirmModal({ title: t('mode.adopt'), children: <Text size="sm">{t('mode.adoptConfirm')}</Text>, labels: { confirm: t('mode.adopt'), cancel: t('common.cancel') }, confirmProps: { color: 'orange' }, onConfirm: () => adopt.mutate(v) }) })}>
              <Group align="flex-end">
                <TextInput flex={2} label={t('mode.captainUrl')} placeholder="https://panel.example.com" required {...mform.getInputProps('url')} />
                <TextInput flex={1} label={t('mode.pairCode')} placeholder="ABCD-EFGH" required {...mform.getInputProps('pair_code')} />
                <Button type="submit" color="orange" loading={adopt.isPending}>{t('mode.adopt')}</Button>
              </Group>
            </form>
          </Stack>
        )}
        {!fixed && s?.mode === 'managed' && (
          <Stack gap="sm">
            <Alert color="orange">{t('mode.managedHint')}</Alert>
            <Text size="sm">{t('mode.managedBy')} <b>{s.managed?.url}</b> · {t('mode.since')} {when(s.managed?.paired_at)}</Text>
            <Switch label={t('mode.keep')} description={t('mode.keepHint')} checked={keep} onChange={(e) => setKeep(e.currentTarget.checked)} />
            {!keep && <Text size="xs" c="dimmed">{s.has_snapshot ? t('mode.restoreHint') : t('mode.emptyHint')}</Text>}
            <Group><Button color="red" variant="light" loading={detach.isPending} onClick={() => modals.openConfirmModal({ title: t('mode.detach'), children: <Text size="sm">{t('mode.detachConfirm')}</Text>, labels: { confirm: t('mode.detach'), cancel: t('common.cancel') }, confirmProps: { color: 'red' }, onConfirm: () => detach.mutate() })}>{t('mode.detach')}</Button></Group>
          </Stack>
        )}
      </Card>

      <SimpleGrid cols={{ base: 1, md: 2 }} mb="lg">
        <TwoFactorCard />
        <TokensCard />
      </SimpleGrid>
      <BackupCard />
      <UpdateCard mb="lg" />

      <Card>
        <Title order={5} mb="xs">{t('settings.cores')}</Title>
        <Text size="xs" c="dimmed" mb="sm">{t('settings.coresHint')}</Text>
        <Table>
          <Table.Thead><Table.Tr><Table.Th>{t('inbounds.core')}</Table.Th><Table.Th>{t('settings.version')}</Table.Th><Table.Th>{t('settings.status')}</Table.Th><Table.Th>{t('settings.note')}</Table.Th></Table.Tr></Table.Thead>
          <Table.Tbody>
            {(cores.data ?? []).map((r) => (
              <Table.Tr key={r.Core + r.Version}>
                <Table.Td><Text size="sm" fw={600}>{r.Core}</Text></Table.Td>
                <Table.Td><Text size="sm" ff="monospace">{r.Version}</Text>{r.Installed && <Badge ml={6} size="xs" color="teal">{t('settings.installed')}</Badge>}</Table.Td>
                <Table.Td><Badge color={r.Status === 'tested' ? 'teal' : r.Status === 'broken' ? 'red' : 'yellow'}>{r.Status}</Badge></Table.Td>
                <Table.Td><Text size="xs" c="dimmed">{r.Note}</Text></Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Card>
    </>
  )
}
