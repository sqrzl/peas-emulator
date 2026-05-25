import {
  DatabaseIcon,
  HomeIcon,
  LogOutIcon,
  MoonIcon,
  SettingsIcon,
  SunIcon,
} from '@askrjs/lucide';
import { Link } from '@askrjs/askr/router';
import { Container, Inline, Stack } from '@askrjs/themes/layouts';
import { Header, Shell, ShellMain, ShellNav } from '@askrjs/themes/shells';
import { NavBrand, NavGroup, NavLink, Sidebar } from '@askrjs/themes/navs';
import { Badge } from '@askrjs/themes/surfaces';
import { ThemeToggle } from '@askrjs/themes/theme';
import { appNavItems } from '../../shared/navigation';

const icons = {
  home: <HomeIcon size={16} aria-hidden="true" />,
  buckets: <DatabaseIcon size={16} aria-hidden="true" />,
  settings: <SettingsIcon size={16} aria-hidden="true" />,
};

export default function AppLayout({ children }: { children?: unknown }) {
  return (
    <Shell variant="sidebar" class="admin-shell">
      <ShellNav>
        <Sidebar
          aria-label="Admin navigation"
          breakpoint="md"
          collapsible="icon"
        >
          <NavBrand>
            <Link href="/app" class="brand-link">
              <span class="brand-mark">A</span>
              <strong>{'ui'}</strong>
            </Link>
          </NavBrand>
          <NavGroup label="Workspace">
            {appNavItems.map((item) => (
              <NavLink key={item.href} href={item.href} match={item.match}>
                <Inline as="span" gap="2" align="center">
                  {icons[item.icon]}
                  <span>{item.label}</span>
                </Inline>
              </NavLink>
            ))}
          </NavGroup>
          <NavGroup label="Session" align="end">
            <NavLink href="/auth/logout" match="exact">
              <Inline as="span" gap="2" align="center">
                <LogOutIcon size={16} aria-hidden="true" />
                <span>Sign out</span>
              </Inline>
            </NavLink>
          </NavGroup>
        </Sidebar>
      </ShellNav>
      <ShellMain>
        <Header position="sticky" class="admin-header">
          <Container size="fluid">
            <Inline justify="between" align="center" gap="3" wrap="wrap">
              <Stack gap="none">
                <span class="eyebrow">Storage console</span>
                <strong>Bucket and object control plane</strong>
              </Stack>
              <Inline gap="2" align="center" wrap="wrap">
                <Badge>live admin API</Badge>
                <ThemeToggle
                  variant="ghost"
                  size="icon"
                  aria-label="Toggle color theme"
                  lightIcon={<SunIcon size={18} aria-hidden="true" />}
                  darkIcon={<MoonIcon size={18} aria-hidden="true" />}
                />
              </Inline>
            </Inline>
          </Container>
        </Header>
        <Container size="fluid" class="admin-main">
          {children}
        </Container>
      </ShellMain>
    </Shell>
  );
}
