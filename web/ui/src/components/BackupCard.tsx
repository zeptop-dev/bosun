import { Button, Card, FileInput, Group, PasswordInput, Stack, Text, Title } from '@mantine/core'
import { modals } from '@mantine/modals'
import { useMutation } from '@tanstack/react-query'
import { IconDownload, IconUpload } from '@tabler/icons-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ApiError, type RestoreResult } from '../lib/api'
import { useAuth } from '../lib/auth'
import { toast } from '../lib/notify'

// Standalone backup: download the node's config as one archive, or restore
// one (replaces local.json and pushed certificates; managed nodes refuse).
export function BackupCard() {
  const { t } = useTranslation()
  const { me, refresh } = useAuth()
  const readOnly = me?.mode !== 'local' || !!me?.fixed
  const [file, setFile] = useState<File | null>(null)
  const [result, setResult] = useState<RestoreResult | null>(null)
  const [passphrase, setPassphrase] = useState('')
  // The archive holds every secret on the node, so it is sealed with the
  // passphrase (AES-256-GCM); an empty passphrase downloads it plain.
  const download = useMutation({
    mutationFn: async () => {
      const res = await fetch('/api/backup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ passphrase }), credentials: 'same-origin' })
      if (!res.ok) throw new ApiError(res.status, res.statusText)
      const blob = await res.blob()
      const name = /filename=([^;]+)/.exec(res.headers.get('Content-Disposition') ?? '')?.[1] ?? 'bosun-backup.tar.gz'
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = name; a.click()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    },
    onError: toast.err,
  })
  const restore = useMutation({
    mutationFn: async (f: File) => {
      const body = new FormData()
      body.append('file', f)
      body.append('passphrase', passphrase)
      const res = await fetch('/api/backup/restore', { method: 'POST', body, credentials: 'same-origin' })
      const text = await res.text()
      const data = text ? JSON.parse(text) : null
      if (!res.ok) throw new ApiError(res.status, data?.error ?? res.statusText)
      return data as RestoreResult
    },
    onSuccess: (r) => { setResult(r); setFile(null); toast.ok(t('backup.restored')); if (r.admin_changed) refresh() },
    onError: toast.err,
  })
  const confirm = () => {
    if (!file) return
    modals.openConfirmModal({ title: t('backup.restore'), children: <Text size="sm">{t('backup.restoreConfirm')}</Text>, labels: { confirm: t('backup.restore'), cancel: t('common.cancel') }, confirmProps: { color: 'red' }, onConfirm: () => restore.mutate(file) })
  }
  return (
    <Card mb="lg">
      <Title order={5} mb="xs">{t('backup.title')}</Title>
      <Text size="xs" c="dimmed" mb="sm">{t('backup.hint')}</Text>
      <Stack gap="sm">
        <Group align="flex-end">
          <PasswordInput label={t('backup.passphrase')} description={t('backup.passphraseHint')} value={passphrase} onChange={(e) => setPassphrase(e.currentTarget.value)} style={{ flex: 1 }} />
          <Button variant="light" mb={22} leftSection={<IconDownload size={16} />} loading={download.isPending} onClick={() => download.mutate()}>{t('backup.download')}</Button>
        </Group>
        {readOnly ? <Text size="xs" c="orange">{t('backup.managedHint')}</Text> : (
          <Group align="flex-end">
            <FileInput label={t('backup.file')} placeholder="bosun-backup-….tar.gz / .enc" accept=".gz,.tgz,.enc,application/gzip,application/octet-stream" value={file} onChange={setFile} style={{ flex: 1 }} clearable />
            <Button color="red" variant="light" leftSection={<IconUpload size={16} />} disabled={!file} loading={restore.isPending} onClick={confirm}>{t('backup.restore')}</Button>
          </Group>
        )}
        {result && (
          <Text size="xs" c="dimmed">
            {t('backup.summary', { inbounds: result.inbounds, users: result.users, forwards: result.forwards, ingresses: result.ingresses })}{result.admin_changed ? ` · ${t('backup.adminChanged')}` : ''}
          </Text>
        )}
      </Stack>
    </Card>
  )
}
