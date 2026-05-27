import { Link } from '@askrjs/askr/router';
import { Button } from '@askrjs/themes/controls';
import { Container, Inline } from '@askrjs/themes/layouts';
import { Header } from '@askrjs/themes/shells';
import { NavBrand, NavGroup, Navbar, NavLink } from '@askrjs/themes/navs';
import { Badge } from '@askrjs/themes/surfaces';
import { MoonIcon, SunIcon } from '@askrjs/lucide';
import { ThemeToggle } from '@askrjs/themes/theme';
import { appNavItems } from '../../shared/navigation';

export default function AppLayout({ children }: { children?: unknown }) {
  return (
    <>
      <Header position="sticky" class="app-header">
        <Container size="fluid">
          <Navbar aria-label="Primary navigation" breakpoint="md">
            <NavBrand>
              <Link href="/app" class="brand-link">
                <span class="brand-mark">P</span>
                <strong>Peas</strong>
              </Link>
            </NavBrand>
            <NavGroup align="center">
              {appNavItems.map((item) => (
                <NavLink key={item.href} href={item.href} match={item.match}>
                  {item.label}
                </NavLink>
              ))}
            </NavGroup>
            <NavGroup align="end">
              <Inline gap="2" align="center" wrap="wrap">
                <Badge>session cookie</Badge>
                <ThemeToggle
                  variant="ghost"
                  size="icon"
                  aria-label="Toggle color theme"
                  lightIcon={<SunIcon size={18} aria-hidden="true" />}
                  darkIcon={<MoonIcon size={18} aria-hidden="true" />}
                />
                <Button variant="secondary" asChild>
                  <Link href="/auth/logout">Sign out</Link>
                </Button>
              </Inline>
            </NavGroup>
          </Navbar>
        </Container>
      </Header>
      <main class="app-main">
        <Container size="fluid">{children}</Container>
      </main>
    </>
  );
}
