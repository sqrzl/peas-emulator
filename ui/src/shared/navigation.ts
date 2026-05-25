export const appNavItems = [
  { href: '/app', label: 'Dashboard', icon: 'home', match: 'exact' as const },
  {
    href: '/app/buckets',
    label: 'Buckets',
    icon: 'buckets',
    match: 'exact' as const,
  },
  {
    href: '/app/settings',
    label: 'Settings',
    icon: 'settings',
    match: 'exact' as const,
  },
] as const;
