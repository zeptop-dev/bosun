import { ActionIcon, AppShell, Avatar, Badge, Box, Burger, Divider, Group, Indicator, Menu, NavLink, ScrollArea, Stack, Text, ThemeIcon, Title, Tooltip, UnstyledButton, useMantineColorScheme } from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconLayoutDashboard, IconPlugConnected, IconUsers, IconSettings, IconLogout, IconLanguage, IconFileText, IconRoute, IconCertificate, IconActivity, IconStethoscope, IconAnchor, IconSun, IconMoon, IconDotsVertical, IconChevronDown } from '@tabler/icons-react'
import { languages } from '../i18n'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useAuth } from '../lib/auth'
import { useQuery } from '@tanstack/react-query'
import { api, type UpdateInfo } from '../lib/api'
import { pageBackground } from '../theme'

// Sidebar groups, separated by hairlines like a hosting console.
const groups = [
  [{ to: '/', key: 'overview', icon: IconLayoutDashboard }],
  [
    { to: '/inbounds', key: 'inbounds', icon: IconPlugConnected },
    { to: '/forwards', key: 'outbound', icon: IconRoute },
    { to: '/users', key: 'users', icon: IconUsers },
    { to: '/certificates', key: 'certificates', icon: IconCertificate },
  ],
  [
    { to: '/probe', key: 'probe', icon: IconActivity },
    { to: '/doctor', key: 'doctor', icon: IconStethoscope },
  ],
  [
    { to: '/settings', key: 'settings', icon: IconSettings },
    { to: '/logs', key: 'logs', icon: IconFileText },
  ],
]

export function ModeBadge({ mode, fixed }: { mode: string; fixed?: string }) {
  const { t } = useTranslation()
  if (fixed) return <Tooltip label={t('mode.fixedHint', { driver: fixed })}><Badge color="grape" variant="filled">{t('mode.fixed', { driver: fixed })}</Badge></Tooltip>
  return mode === 'managed'
    ? <Tooltip label={t('mode.managedHint')}><Badge color="orange" variant="filled">{t('mode.managed')}</Badge></Tooltip>
    : <Badge color="teal" variant="light">{t('mode.local')}</Badge>
}

export function Brand({ name, size = 'md' }: { name: string; size?: 'md' | 'lg' }) {
  return (
    <Group gap="xs" wrap="nowrap">
      <ThemeIcon size={size === 'lg' ? 40 : 30} radius="md" variant="filled"><IconAnchor size={size === 'lg' ? 24 : 18} stroke={2} /></ThemeIcon>
      <Text fw={700} size={size === 'lg' ? 'xl' : 'lg'} style={{ letterSpacing: '-0.01em' }}>{name}</Text>
    </Group>
  )
}

export function AppLayout() {
  const [opened, { toggle, close }] = useDisclosure()
  const { t, i18n } = useTranslation()
  const { me, logout } = useAuth()
  const nav = useNavigate()
  const loc = useLocation()
  const { colorScheme, setColorScheme } = useMantineColorScheme()
  const active = (to: string) => (to === '/' ? loc.pathname === '/' : loc.pathname.startsWith(to))
  const current = groups.flat().find((it) => active(it.to))
  const upd = useQuery({ queryKey: ['update'], queryFn: () => api.get<UpdateInfo>('/api/update'), staleTime: 10 * 60_000, refetchInterval: 30 * 60_000, retry: false })
  const lang = languages.find((l) => l.code === i18n.language) ?? languages[0]
  const dark = colorScheme === 'dark'

  return (
    <AppShell navbar={{ width: 248, breakpoint: 'sm', collapsed: { mobile: !opened } }} header={{ height: 56 }} padding="lg" styles={{ main: { background: pageBackground } }}>
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between" wrap="nowrap">
          <Group gap="sm" wrap="nowrap">
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
            <Box hiddenFrom="sm"><Brand name="bosun" /></Box>
            <Title order={4} visibleFrom="sm">{current ? t(`nav.${current.key}`) : 'bosun'}</Title>
          </Group>
          <Group gap="xs" wrap="nowrap">
            {me && <ModeBadge mode={me.mode} fixed={me.fixed} />}
            {me?.version && (
              <Indicator disabled={!upd.data?.has_update} color="red" size={8} offset={2} processing>
                <Badge size="sm" variant="default" style={{ cursor: 'pointer' }} onClick={() => nav('/settings')} title={upd.data?.has_update ? t('update.available', { version: upd.data.latest }) : undefined}>{me.version}</Badge>
              </Indicator>
            )}
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar>
        <AppShell.Section h={56} px="md" style={{ display: 'flex', alignItems: 'center', borderBottom: '1px solid var(--mantine-color-default-border)' }}>
          <UnstyledButton onClick={() => { nav('/'); close() }}><Brand name="bosun" /></UnstyledButton>
        </AppShell.Section>
        <AppShell.Section grow component={ScrollArea} type="auto" scrollbarSize={6} px="sm" py="sm">
          <Stack gap={0}>
            {groups.map((g, i) => (
              <Box key={i}>
                {i > 0 && <Divider my="xs" />}
                {g.map((it) => (
                  <NavLink key={it.to} component={UnstyledButton} label={t(`nav.${it.key}`)} leftSection={<it.icon size={18} stroke={1.7} />}
                    variant="light" active={active(it.to)} onClick={() => { nav(it.to); close() }}
                    styles={{ root: { borderRadius: 8, marginBottom: 2 }, label: { fontWeight: 500 } }} />
                ))}
              </Box>
            ))}
          </Stack>
        </AppShell.Section>
        <AppShell.Section p="sm" style={{ borderTop: '1px solid var(--mantine-color-default-border)' }}>
          <Group justify="space-between" mb="sm" px={4}>
            <Menu shadow="md" width={160}>
              <Menu.Target>
                <UnstyledButton aria-label="language">
                  <Group gap={6}><IconLanguage size={16} stroke={1.7} /><Text size="sm" fw={500}>{lang.label}</Text><IconChevronDown size={14} opacity={0.6} /></Group>
                </UnstyledButton>
              </Menu.Target>
              <Menu.Dropdown>
                {languages.map((l) => <Menu.Item key={l.code} fw={i18n.language === l.code ? 700 : undefined} onClick={() => i18n.changeLanguage(l.code)}>{l.label}</Menu.Item>)}
              </Menu.Dropdown>
            </Menu>
            <ActionIcon variant="subtle" color="gray" aria-label="color scheme" onClick={() => setColorScheme(dark ? 'light' : 'dark')}>{dark ? <IconSun size={18} /> : <IconMoon size={18} />}</ActionIcon>
          </Group>
          <Group gap="sm" wrap="nowrap" p="xs" style={{ border: '1px solid var(--mantine-color-default-border)', borderRadius: 12 }}>
            <Avatar radius="xl" color="brand" variant="light">{(me?.username ?? '?').slice(0, 1).toUpperCase()}</Avatar>
            <Box style={{ flex: 1, minWidth: 0 }}>
              <Text size="sm" fw={600} truncate>{me?.username}</Text>
              <Text size="xs" c="dimmed" truncate>{me ? t(`mode.${me.mode}`) : ''}</Text>
            </Box>
            <Menu shadow="md" position="top-end">
              <Menu.Target><ActionIcon variant="subtle" color="gray" aria-label="account menu"><IconDotsVertical size={18} /></ActionIcon></Menu.Target>
              <Menu.Dropdown>
                <Menu.Item leftSection={<IconSettings size={16} />} onClick={() => { nav('/settings'); close() }}>{t('nav.settings')}</Menu.Item>
                <Menu.Item leftSection={<IconLogout size={16} />} color="red" onClick={async () => { await logout(); nav('/login') }}>{t('common.logout')}</Menu.Item>
              </Menu.Dropdown>
            </Menu>
          </Group>
        </AppShell.Section>
      </AppShell.Navbar>

      <AppShell.Main><Outlet /></AppShell.Main>
    </AppShell>
  )
}
