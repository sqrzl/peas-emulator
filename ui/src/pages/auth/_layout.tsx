import { MoonIcon, SunIcon } from '@askrjs/lucide';
import { Link } from '@askrjs/askr/router';
import { Button } from '@askrjs/themes/controls';
import { Container, Inline } from '@askrjs/themes/layouts';
import { Header } from '@askrjs/themes/shells';
import { NavBrand, NavGroup, Navbar, NavLink } from '@askrjs/themes/navs';
import { ThemeToggle } from '@askrjs/themes/theme';

export default function AuthLayout({ children }: { children?: unknown }) {
  return (
    <>
      <Header position="sticky">
        <Container>
          <Navbar aria-label="Authentication navigation" breakpoint="md">
            <NavBrand>
              <Link href="/auth" class="brand-link">
                <span class="brand-mark">A</span>
                <strong>{'ui'}</strong>
              </Link>
            </NavBrand>
            <NavGroup align="center">
              <NavLink href="/auth" match="exact">
                Login
              </NavLink>
              <NavLink href="/auth/logout">Logout</NavLink>
            </NavGroup>
            <NavGroup align="end">
              <Inline gap="2" align="center">
                <ThemeToggle
                  variant="ghost"
                  size="icon"
                  aria-label="Toggle color theme"
                  lightIcon={<SunIcon size={18} aria-hidden="true" />}
                  darkIcon={<MoonIcon size={18} aria-hidden="true" />}
                />
                <Button asChild>
                  <Link href="/app">Open console</Link>
                </Button>
              </Inline>
            </NavGroup>
          </Navbar>
        </Container>
      </Header>
      <main>{children}</main>
    </>
  );
}
