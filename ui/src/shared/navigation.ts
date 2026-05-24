export const appNavItems = [
  { href: '/app', label: 'Dashboard', icon: 'home', match: 'exact' as const },
  {
    href: '/app/agents',
    label: 'Agent runs',
    icon: 'agents',
    match: 'exact' as const,
  },
  {
    href: '/app/settings',
    label: 'Settings',
    icon: 'settings',
    match: 'exact' as const,
  },
] as const;
