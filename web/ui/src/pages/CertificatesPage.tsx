import { ActionIcon, Badge, Button, Card, Code, Group, Modal, Stack, Table, Text, TextInput, Textarea, Title } from '@mantine/core'
import { useForm } from '@mantine/form'
import { modals } from '@mantine/modals'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconPlus, IconTrash } from '@tabler/icons-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, type Certificate, type Status } from '../lib/api'
import { useAuth } from '../lib/auth'
import { when } from '../lib/format'
import { toast } from '../lib/notify'
import { PageHeader } from '../components/PageHeader'

const daysLeft = (iso: string) => Math.floor((new Date(iso).getTime() - Date.now()) / 86400e3)

// Certificates on this node: PEM pairs the operator uploads (used ahead of
// ACME for the names they cover) and the automatic ones bosun obtained.
export default function CertificatesPage() {
  const { t } = useTranslation()
  const { me } = useAuth()
  const qc = useQueryClient()
  const readOnly = me?.mode !== 'local' || !!me?.fixed
  const q = useQuery({ queryKey: ['certificates'], queryFn: () => api.get<Certificate[]>('/api/certificates') })
  const status = useQuery({ queryKey: ['status'], queryFn: () => api.get<Status>('/api/status'), refetchInterval: 15_000 })
  const [uploading, setUploading] = useState(false)
  const form = useForm({ initialValues: { domain: '', cert_pem: '', key_pem: '' }, validate: { cert_pem: (v) => (v.trim() ? null : t('form.required')), key_pem: (v) => (v.trim() ? null : t('form.required')) } })
  const invalidate = () => qc.invalidateQueries({ queryKey: ['certificates'] })
  const upload = useMutation({ mutationFn: (v: typeof form.values) => api.post('/api/certificates', v), onSuccess: () => { toast.ok(t('common.saved')); setUploading(false); form.reset(); invalidate() }, onError: toast.err })
  const del = useMutation({ mutationFn: (domain: string) => api.del(`/api/certificates/${encodeURIComponent(domain)}`), onSuccess: () => { toast.ok(t('common.deleted')); invalidate() }, onError: toast.err })
  const expiry = (iso: string) => { const d = daysLeft(iso); return <Text size="xs" c={d < 14 ? 'red' : d < 30 ? 'orange' : 'dimmed'}>{d < 0 ? t('certs.expired') : t('certs.daysLeft', { n: d })} · {when(iso).split(',')[0]}</Text> }
  const auto = status.data?.certs ?? []
  return (
    <>
      <PageHeader title={t('certs.title')} subtitle={t('certs.subtitle')} actions={!readOnly && <Button leftSection={<IconPlus size={16} />} onClick={() => setUploading(true)}>{t('certs.upload')}</Button>} />
      <Card p={0} mb="lg">
        <Table>
          <Table.Thead><Table.Tr><Table.Th>{t('certs.domain')}</Table.Th><Table.Th>{t('certs.names')}</Table.Th><Table.Th>{t('certs.issuer')}</Table.Th><Table.Th>{t('certs.expiry')}</Table.Th><Table.Th /></Table.Tr></Table.Thead>
          <Table.Tbody>
            {(q.data ?? []).map((c) => (
              <Table.Tr key={c.domain}>
                <Table.Td><Code>{c.domain}</Code></Table.Td>
                <Table.Td><Text size="xs" c="dimmed">{(c.names ?? []).filter((n) => n !== c.domain).join(', ') || '—'}</Text></Table.Td>
                <Table.Td><Text size="xs">{c.issuer || '—'}</Text></Table.Td>
                <Table.Td>{expiry(c.not_after)}</Table.Td>
                <Table.Td><Group justify="flex-end">{!readOnly && <ActionIcon variant="subtle" color="red" onClick={() => modals.openConfirmModal({ title: t('common.delete'), children: <Text size="sm">{t('certs.deleteHint')}</Text>, labels: { confirm: t('common.delete'), cancel: t('common.cancel') }, confirmProps: { color: 'red' }, onConfirm: () => del.mutate(c.domain) })}><IconTrash size={16} /></ActionIcon>}</Group></Table.Td>
              </Table.Tr>
            ))}
            {(q.data ?? []).length === 0 && <Table.Tr><Table.Td colSpan={5}><Text c="dimmed" ta="center" py="lg">{t('certs.empty')}</Text></Table.Td></Table.Tr>}
          </Table.Tbody>
        </Table>
      </Card>

      <Card>
        <Title order={5} mb={4}>{t('settings.certList')}</Title>
        <Text size="xs" c="dimmed" mb="sm">{t('certs.autoHint')}</Text>
        {auto.length === 0 ? <Text size="sm" c="dimmed">{t('common.empty')}</Text> : (
          <Table>
            <Table.Thead><Table.Tr><Table.Th>{t('settings.domain')}</Table.Th><Table.Th>{t('inbounds.acme')}</Table.Th><Table.Th>{t('settings.expires')}</Table.Th><Table.Th>{t('settings.status')}</Table.Th></Table.Tr></Table.Thead>
            <Table.Tbody>
              {auto.map((c) => (
                <Table.Tr key={c.domain}>
                  <Table.Td><Text size="sm" ff="monospace">{c.domain}</Text></Table.Td>
                  <Table.Td><Badge variant="outline" color="gray">{c.method}</Badge></Table.Td>
                  <Table.Td>{c.not_after && !c.not_after.startsWith('0001') ? expiry(c.not_after) : <Text size="sm">—</Text>}</Table.Td>
                  <Table.Td>{c.error ? <Text size="xs" c="red">{c.error}</Text> : <Badge color="teal">{t('settings.certOk')}</Badge>}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Card>

      <Modal opened={uploading} onClose={() => setUploading(false)} title={t('certs.upload')} size="lg">
        <form onSubmit={form.onSubmit((v) => upload.mutate(v))}><Stack>
          <TextInput label={t('certs.domain')} description={t('certs.domainHint')} placeholder="*.example.com" {...form.getInputProps('domain')} />
          <Textarea label={t('certs.cert')} placeholder="-----BEGIN CERTIFICATE-----" autosize minRows={4} maxRows={8} required styles={{ input: { fontFamily: 'monospace', fontSize: 11 } }} {...form.getInputProps('cert_pem')} />
          <Textarea label={t('certs.key')} placeholder="-----BEGIN PRIVATE KEY-----" autosize minRows={4} maxRows={8} required styles={{ input: { fontFamily: 'monospace', fontSize: 11 } }} {...form.getInputProps('key_pem')} />
          <Group justify="flex-end"><Button variant="default" onClick={() => setUploading(false)}>{t('common.cancel')}</Button><Button type="submit" loading={upload.isPending}>{t('certs.upload')}</Button></Group>
        </Stack></form>
      </Modal>
    </>
  )
}
