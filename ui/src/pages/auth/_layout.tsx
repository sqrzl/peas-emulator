import { MoonIcon, SunIcon } from '@askrjs/lucide';
import { Link } from '@askrjs/askr/router';
import { Container, Inline } from '@askrjs/themes/layouts';
import { Header } from '@askrjs/themes/shells';
import { NavBrand, NavGroup, Navbar } from '@askrjs/themes/navs';
import { Badge } from '@askrjs/themes/surfaces';
import { ThemeToggle } from '@askrjs/themes/theme';

export default function AuthLayout({ children }: { children?: unknown }) {
  return (
    <>
      <Header position="sticky" class="auth-header">
        <Container size="fluid">
          <Navbar aria-label="Authentication navigation" breakpoint="md">
            <NavBrand>
              <Link href="/auth" class="brand-link">
                <span class="brand-mark">P</span>
                <strong>Peas</strong>
              </Link>
            </NavBrand>
            <NavGroup align="end">
              <Inline gap="2" align="center">
                <Badge>session cookie</Badge>
                <ThemeToggle
                  variant="ghost"
                  size="icon"
                  aria-label="Toggle color theme"
                  lightIcon={<SunIcon size={18} aria-hidden="true" />}
                  darkIcon={<MoonIcon size={18} aria-hidden="true" />}
                />
              </Inline>
            </NavGroup>
          </Navbar>
        </Container>
      </Header>
      <main class="auth-main">{children}</main>
    </>
  );
}
