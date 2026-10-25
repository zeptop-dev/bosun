import { ActionIcon, Alert, Button, Card, Checkbox, Code, Group, Modal, MultiSelect, NumberInput, Select, Stack, Table, Text, TextInput, Title, Tooltip } from '@mantine/core'
import { useDebouncedValue } from '@mantine/hooks'
import { modals } from '@mantine/modals'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { IconArrowDown, IconArrowUp, IconPlus, IconTrash } from '@tabler/icons-react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import { toast } from '../lib/notify'

interface DGroup { name: string; type: string; members: string[]; url?: string; interval?: number }
interface DRule { set: string; policy: string }
interface Design { groups: DGroup[]; rules: DRule[]; final: string }
interface Data { design: Design; catalogue: { key: string; name: string; url?: string }[]; presets: { key: string; name: string }[]; regions: { name: string; match: string }[]; tags: string[]; formats: string[] }
interface FormatSupport { format: string; supported: boolean; reasons: string[]; reason_codes: string[]; warnings: string[]; warning_codes: string[] }
interface Inspection { formats: FormatSupport[] }
interface Snapshot { design: Design; epoch: number }
interface ApplySnapshot extends Snapshot { formats: string[] }

const groupTypes = ['select', 'url-test', 'fallback', 'load-balance']
const formatLabels: Record<string, string> = { clash: 'mihomo / Clash Meta', stash: 'Stash', surge: 'Surge', surfboard: 'Surfboard', loon: 'Loon', qx: 'Quantumult X', egern: 'Egern' }

// Visual editor for the subscription document: proxy groups (members by
// group, all servers, tag or name pattern) and an ordered rule list drawn
// from the ACL4SSR catalogue. "Apply" generates only explicitly selected formats.
export function SubDesigner() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['sub-design'], queryFn: () => api.get<Data>('/api/sub-design') })
  const [d, setD] = useState<Design>({ groups: [], rules: [], final: '' })
  const [dirty, setDirty] = useState(false)
  const [preview, setPreview] = useState<{ format: string; text: string } | null>(null)
  const [previewFormat, setPreviewFormat] = useState('clash')
  const [selectedFormats, setSelectedFormats] = useState<string[]>([])
  const epoch = useRef(0)
  useEffect(() => { if (q.data && !dirty) { setD(q.data.design); setSelectedFormats([]) } }, [q.data, dirty])
  const edit = (f: (x: Design) => Design) => { epoch.current++; setD((x) => f(structuredClone(x))); setDirty(true); setSelectedFormats([]) }

  const loadPreset = useMutation({ mutationFn: (key: string) => api.get<Design>(`/api/sub-design/presets/${key}`), onSuccess: (r) => { epoch.current++; setD(r); setDirty(true); setSelectedFormats([]) }, onError: toast.err })
  const acceptSaved = (submitted: Snapshot) => {
    if (epoch.current === submitted.epoch) {
      qc.setQueryData<Data>(['sub-design'], current => current ? { ...current, design: submitted.design } : current)
      setDirty(false)
    }
    qc.invalidateQueries({ queryKey: ['sub-design'], exact: true })
  }
  const save = useMutation({ mutationFn: (submitted: Snapshot) => api.put('/api/sub-design', { design: submitted.design }), onSuccess: (_, submitted) => { toast.ok(t('common.saved')); acceptSaved(submitted) }, onError: toast.err })
  const apply = useMutation({ mutationFn: (submitted: ApplySnapshot) => api.post('/api/sub-design/apply', { design: submitted.design, formats: submitted.formats }), onSuccess: (_, submitted) => { toast.ok(t('subDesign.applied')); acceptSaved(submitted); qc.invalidateQueries({ queryKey: ['sub-templates'] }) }, onError: toast.err })
  const doPreview = useMutation({ mutationFn: (format: string) => api.post<{ format: string; text: string }>('/api/sub-design/preview', { design: d, format }), onSuccess: setPreview, onError: toast.err })

  const [debounced] = useDebouncedValue(d, 300)
  const inspection = useQuery({
    queryKey: ['sub-design-inspect', debounced],
    queryFn: ({ signal }) => api.post<Inspection>('/api/sub-design/inspect', { design: debounced }, signal),
    enabled: !!q.data,
    retry: false,
    staleTime: 30_000,
  })
  const inspectionCurrent = JSON.stringify(debounced) === JSON.stringify(d) && inspection.isSuccess && !inspection.isFetching
  const support = inspectionCurrent ? inspection.data.formats : []
  const canApply = inspectionCurrent && selectedFormats.length > 0 && selectedFormats.every(format => support.some(item => item.format === format && item.supported))
  const supportMessage = (code: string | undefined, detail: string) => {
    const messages: Record<string, string> = {
      'dns-direct-only': t('subDesign.supportDNSDirectOnly'),
      'dns-loon-policy-unverified': t('subDesign.supportDNSLoonPolicy'),
      'dns-qx-policy-unavailable': t('subDesign.supportDNSQXPolicy'),
      invalid_design: t('subDesign.supportInvalidDesign', { detail }),
      inline_rule_unsupported: t('subDesign.supportInlineRule', { detail }),
      remote_rules_unsupported: t('subDesign.supportRemoteRules', { detail }),
      udp_rule_order_unsupported: t('subDesign.supportUDPRuleOrder'),
      group_timeout_unsupported: t('subDesign.supportGroupTimeout', { detail }),
      group_test_url_unsupported: t('subDesign.supportGroupTestURL', { detail }),
      group_test_url_http: t('subDesign.supportHTTPTestURL'),
      'dns-stash-version': t('subDesign.warningDNSStashVersion'),
      'dns-surge-ip-proxies': t('subDesign.warningDNSSurgeIPProxies'),
      'dns-domestic-suffix-only': t('subDesign.warningDNSDomesticSuffix'),
      'dns-egern-proxy-direct': t('subDesign.warningDNSEgernProxyDirect'),
      native_rule_priority: t('subDesign.warningNativeRulePriority'),
      remote_process_macos: t('subDesign.warningRemoteProcessMacOS'),
      remote_native_unsupported: t('subDesign.warningRemoteNativeUnsupported'),
      loon_rule_version: t('subDesign.warningLoonRuleVersion'),
      qx_udp_tunnel: t('subDesign.warningQXUDPTunnel'),
    }
    return code && messages[code] ? messages[code] : detail
  }

  const names = d.groups.map((g) => g.name).filter(Boolean)
  const policies = [...names, 'DIRECT', 'REJECT']
  const memberOptions = (self: string) => [
    { group: t('subDesign.memberServers'), items: [
      { value: '@all', label: t('subDesign.allServers') },
      ...(q.data?.tags ?? []).map((tag) => ({ value: `@tag:${tag}`, label: t('subDesign.tag', { tag }) })),
      ...(q.data?.regions ?? []).map((r) => ({ value: `@match:${r.match}`, label: r.name })),
    ] },
    { group: t('subDesign.memberGroups'), items: [...names.filter((n) => n !== self).map((n) => ({ value: n, label: n })), { value: 'DIRECT', label: 'DIRECT' }, { value: 'REJECT', label: 'REJECT' }] },
  ]
  const move = <T,>(list: T[], i: number, dir: -1 | 1) => { const j = i + dir; if (j < 0 || j >= list.length) return list; const c = [...list]; ;[c[i], c[j]] = [c[j], c[i]]; return c }
  const catalogue = q.data?.catalogue ?? []

  return (
    <Stack gap="md">
      <Card>
        <Group justify="space-between" align="flex-end" wrap="wrap">
          <div>
            <Title order={5}>{t('subDesign.title')}</Title>
            <Text size="xs" c="dimmed" mt={4}>{t('subDesign.hint')}</Text>
          </div>
          <Select size="xs" placeholder={t('subDesign.loadPreset')} data={(q.data?.presets ?? []).map((p) => ({ value: p.key, label: p.name }))} value={null} onChange={(v) => v && modals.openConfirmModal({ title: t('subDesign.loadPreset'), children: <Text size="sm">{t('subDesign.presetConfirm')}</Text>, labels: { confirm: t('common.confirm'), cancel: t('common.cancel') }, onConfirm: () => loadPreset.mutate(v) })} w={360} />
        </Group>
      </Card>

      <Card>
        <Group justify="space-between" mb="sm"><Title order={6}>{t('subDesign.groups')}</Title><Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={() => edit((x) => ({ ...x, groups: [...x.groups, { name: '', type: 'select', members: ['@all'] }] }))}>{t('subDesign.addGroup')}</Button></Group>
        <Text size="xs" c="dimmed" mb="sm">{t('subDesign.groupsHint')}</Text>
        <Stack gap="xs">
          {d.groups.map((g, i) => (
            <Group key={i} align="flex-start" wrap="nowrap" gap="xs">
              <TextInput size="xs" w={170} placeholder={t('subDesign.groupName')} value={g.name} onChange={(e) => { const v = e.currentTarget.value; edit((x) => { const old = x.groups[i].name; x.groups[i].name = v; x.groups.forEach((gg) => { gg.members = gg.members.map((m) => (m === old && old ? v : m)) }); x.rules.forEach((r) => { if (r.policy === old && old) r.policy = v }); if (x.final === old && old) x.final = v; return x }) }} />
              <Select size="xs" w={130} data={groupTypes} value={g.type} onChange={(v) => v && edit((x) => { x.groups[i].type = v; return x })} allowDeselect={false} />
              <MultiSelect size="xs" flex={1} data={memberOptions(g.name)} value={g.members} onChange={(v) => edit((x) => { x.groups[i].members = v; return x })} searchable placeholder={t('subDesign.members')} />
              {g.type !== 'select' && <NumberInput size="xs" w={90} min={30} value={g.interval ?? 300} onChange={(v) => edit((x) => { x.groups[i].interval = Number(v) || 300; return x })} suffix=" s" />}
              <Group gap={2} wrap="nowrap">
                <ActionIcon size="sm" variant="subtle" onClick={() => edit((x) => ({ ...x, groups: move(x.groups, i, -1) }))}><IconArrowUp size={14} /></ActionIcon>
                <ActionIcon size="sm" variant="subtle" onClick={() => edit((x) => ({ ...x, groups: move(x.groups, i, 1) }))}><IconArrowDown size={14} /></ActionIcon>
                <ActionIcon size="sm" variant="subtle" color="red" onClick={() => edit((x) => ({ ...x, groups: x.groups.filter((_, k) => k !== i) }))}><IconTrash size={14} /></ActionIcon>
              </Group>
            </Group>
          ))}
          {d.groups.length === 0 && <Text size="sm" c="dimmed">{t('subDesign.noGroups')}</Text>}
        </Stack>
      </Card>

      <Card>
        <Group justify="space-between" mb="sm"><Title order={6}>{t('subDesign.rules')}</Title><Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={() => edit((x) => ({ ...x, rules: [...x.rules, { set: catalogue[0]?.key ?? '', policy: policies[0] ?? 'DIRECT' }] }))}>{t('subDesign.addRule')}</Button></Group>
        <Text size="xs" c="dimmed" mb="sm">{t('subDesign.rulesHint')}</Text>
        <Table fz="xs" verticalSpacing={4}><Table.Tbody>
          {d.rules.map((r, i) => (
            <Table.Tr key={i}>
              <Table.Td w={40}><Text c="dimmed">{i + 1}</Text></Table.Td>
              <Table.Td><Select size="xs" data={catalogue.map((c) => ({ value: c.key, label: c.name }))} value={r.set} onChange={(v) => v && edit((x) => { x.rules[i].set = v; return x })} allowDeselect={false} searchable /></Table.Td>
              <Table.Td w={220}><Select size="xs" data={policies} value={r.policy} onChange={(v) => v && edit((x) => { x.rules[i].policy = v; return x })} allowDeselect={false} /></Table.Td>
              <Table.Td w={100}><Group gap={2} wrap="nowrap">
                <ActionIcon size="sm" variant="subtle" onClick={() => edit((x) => ({ ...x, rules: move(x.rules, i, -1) }))}><IconArrowUp size={14} /></ActionIcon>
                <ActionIcon size="sm" variant="subtle" onClick={() => edit((x) => ({ ...x, rules: move(x.rules, i, 1) }))}><IconArrowDown size={14} /></ActionIcon>
                <ActionIcon size="sm" variant="subtle" color="red" onClick={() => edit((x) => ({ ...x, rules: x.rules.filter((_, k) => k !== i) }))}><IconTrash size={14} /></ActionIcon>
              </Group></Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody></Table>
        <Group mt="sm" align="flex-end">
          <Select size="xs" label={t('subDesign.final')} description={t('subDesign.finalHint')} w={260} data={policies} value={d.final || null} onChange={(v) => v && edit((x) => ({ ...x, final: v }))} allowDeselect={false} />
        </Group>
      </Card>

      <Card>
        <Title order={6}>{t('subDesign.formatSupport')}</Title>
        <Text size="xs" c="dimmed" mt={4} mb="sm">{t('subDesign.formatsHint')}</Text>
        {!inspectionCurrent && !inspection.isError && <Text size="sm" c="dimmed" mb="sm">{t('subDesign.checking')}</Text>}
        {inspection.isError && <Alert color="red" mb="sm">{t('subDesign.checkFailed', { detail: inspection.error.message })}</Alert>}
        {inspectionCurrent && <Stack gap="xs" mb="md">
          {support.map(item => <div key={item.format}>
            <Checkbox label={`${formatLabels[item.format] ?? item.format} · ${t(item.supported ? 'subDesign.supported' : 'subDesign.unsupported')}`} checked={selectedFormats.includes(item.format)} disabled={!item.supported || apply.isPending} onChange={event => { const checked = event.currentTarget.checked; setSelectedFormats(current => checked ? [...current, item.format] : current.filter(format => format !== item.format)) }} />
            {item.reasons.map((reason, index) => <Text key={`reason-${index}`} size="xs" c="red" ml={28} mt={3}>{supportMessage(item.reason_codes[index], reason)}</Text>)}
            {item.warnings.map((warning, index) => <Text key={`warning-${index}`} size="xs" c="orange" ml={28} mt={3}>{supportMessage(item.warning_codes[index], warning)}</Text>)}
          </div>)}
          <Button size="xs" variant="subtle" w="fit-content" disabled={apply.isPending || !support.some(item => item.supported)} onClick={() => setSelectedFormats(support.filter(item => item.supported).map(item => item.format))}>{t('subDesign.selectSupported')}</Button>
        </Stack>}
        <Group justify="space-between" wrap="wrap">
          <Group gap="xs">
            <Select size="xs" w={200} data={(q.data?.formats ?? []).map((f) => ({ value: f, label: formatLabels[f] ?? f, disabled: !support.some(item => item.format === f && item.supported) }))} value={previewFormat} onChange={(v) => v && setPreviewFormat(v)} allowDeselect={false} />
            <Button size="xs" variant="default" disabled={!support.some(item => item.format === previewFormat && item.supported)} loading={doPreview.isPending} onClick={() => doPreview.mutate(previewFormat)}>{t('subDesign.preview')}</Button>
          </Group>
          <Group gap="xs">
            <Tooltip label={t('subDesign.saveHint')}><Button size="xs" variant="default" loading={save.isPending} disabled={apply.isPending} onClick={() => save.mutate({ design: structuredClone(d), epoch: epoch.current })}>{t('subDesign.save')}</Button></Tooltip>
            <Button size="xs" loading={apply.isPending} disabled={!canApply || save.isPending} onClick={() => {
              const submitted = { design: structuredClone(d), epoch: epoch.current, formats: [...selectedFormats] }
              modals.openConfirmModal({ title: t('subDesign.apply'), children: <Text size="sm">{t('subDesign.applyConfirm', { formats: submitted.formats.map(format => formatLabels[format] ?? format).join(', ') })}</Text>, labels: { confirm: t('subDesign.apply'), cancel: t('common.cancel') }, onConfirm: () => apply.mutate(submitted) })
            }}>{t('subDesign.apply')}</Button>
          </Group>
        </Group>
        <Text size="xs" c="dimmed" mt="xs">{t('subDesign.applyHint')} <Code>{'{{proxy_names:tag=hk}}'}</Code> <Code>{'{{proxy_names:match=HK|香港}}'}</Code></Text>
      </Card>

      <Modal opened={preview !== null} onClose={() => setPreview(null)} title={preview ? formatLabels[preview.format] ?? preview.format : ''} size="xl">
        <Code block style={{ maxHeight: '70vh', overflow: 'auto', fontSize: 12, whiteSpace: 'pre' }}>{preview?.text}</Code>
      </Modal>
    </Stack>
  )
}
