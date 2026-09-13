import { ActionIcon, AppShell, Badge, Box, Burger, Group, Menu, NavLink, Stack, Text, Tooltip, UnstyledButton } from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconLayoutDashboard, IconPlugConnected, IconUsers, IconArrowsRightLeft, IconSettings, IconLogout, IconLanguage, IconFileText, IconRoute, IconCertificate, IconActivity, IconTopologyStar } from '@tabler/icons-react'
import { languages } from '../i18n'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useAuth } from '../lib/auth'
import { useQuery } from '@tanstack/react-query'
import { api, type UpdateInfo } from '../lib/api'
import { Indicator } from '@mantine/core'

const items = [
  { to: '/', key: 'overview', icon: IconLayoutDashboard },
  { to: '/inbounds', key: 'inbounds', icon: IconPlugConnected },
  { to: '/users', key: 'users', icon: IconUsers },
  { to: '/forwards', key: 'forwards', icon: IconArrowsRightLeft },
  { to: '/ingresses', key: 'ingresses', icon: IconTopologyStar },
  { to: '/routing', key: 'routing', icon: IconRoute },
  { to: '/certificates', key: 'certificates', icon: IconCertificate },
  { to: '/probe', key: 'probe', icon: IconActivity },
  { to: '/settings', key: 'settings', icon: IconSettings },
  { to: '/logs', key: 'logs', icon: IconFileText },
]

export function ModeBadge({ mode, fixed }: { mode: string; fixed?: string }) {
  const { t } = useTranslation()
  if (fixed) return <Tooltip label={t('mode.fixedHint', { driver: fixed })}><Badge color="grape" variant="filled">{t('mode.fixed', { driver: fixed })}</Badge></Tooltip>
  return mode === 'managed'
    ? <Tooltip label={t('mode.managedHint')}><Badge color="orange" variant="filled">{t('mode.managed')}</Badge></Tooltip>
    : <Badge color="teal" variant="light">{t('mode.local')}</Badge>
}

export function AppLayout() {
  const [opened, { toggle, close }] = useDisclosure()
  const { t, i18n } = useTranslation()
  const { me, logout } = useAuth()
  const nav = useNavigate()
  const loc = useLocation()
  const active = (to: string) => (to === '/' ? loc.pathname === '/' : loc.pathname.startsWith(to))
  const upd = useQuery({ queryKey: ['update'], queryFn: () => api.get<UpdateInfo>('/api/update'), staleTime: 10 * 60_000, refetchInterval: 30 * 60_000, retry: false })

  return (
    <AppShell navbar={{ width: 220, breakpoint: 'sm', collapsed: { mobile: !opened } }} header={{ height: 52 }} padding="lg">
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Group gap="sm">
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
            <Text fw={700} size="lg" style={{ letterSpacing: '0.02em' }}>bosun</Text>
            {me?.version && <Indicator disabled={!upd.data?.has_update} color="red" size={8} offset={2} processing><Badge size="xs" variant="outline" color="gray" style={{ cursor: 'pointer' }} onClick={() => nav('/settings')} title={upd.data?.has_update ? t('update.available', { version: upd.data.latest }) : undefined}>{me.version}</Badge></Indicator>}
            {me && <ModeBadge mode={me.mode} fixed={me.fixed} />}
          </Group>
          <Group gap="xs">
            <Menu shadow="md">
              <Menu.Target><ActionIcon variant="subtle" color="gray" aria-label="language"><IconLanguage size={18} /></ActionIcon></Menu.Target>
              <Menu.Dropdown>
                {languages.map((l) => <Menu.Item key={l.code} fw={i18n.language === l.code ? 700 : undefined} onClick={() => i18n.changeLanguage(l.code)}>{l.label}</Menu.Item>)}
              </Menu.Dropdown>
            </Menu>
            <Text size="sm" c="dimmed">{me?.username}</Text>
            <ActionIcon variant="subtle" color="gray" aria-label="logout" onClick={async () => { await logout(); nav('/login') }}><IconLogout size={18} /></ActionIcon>
          </Group>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar p="sm">
        <Stack gap={2}>
          <Box>
            {items.map((it) => (
              <NavLink key={it.to} component={UnstyledButton} label={t(`nav.${it.key}`)} leftSection={<it.icon size={18} stroke={1.6} />}
                active={active(it.to)} onClick={() => { nav(it.to); close() }} style={{ borderRadius: 8 }} />
            ))}
          </Box>
        </Stack>
      </AppShell.Navbar>
      <AppShell.Main><Outlet /></AppShell.Main>
    </AppShell>
  )
}
