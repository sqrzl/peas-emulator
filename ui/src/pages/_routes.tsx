import { fallback, group, registerRoutes } from '@askrjs/askr/router';
import RootLayout from './_layout';
import { registerAppRoutes } from './app/_routes';
import AppLayout from './app/_layout';
import NotFoundPage from './not-found';
import { registerGuestRoutes, registerLogoutRoute } from './auth/_routes';
import AuthLayout from './auth/_layout';
import { resolveAdminSession } from '../features/auth/admin-session';

registerRoutes(
  () => {
    group({ layout: RootLayout }, () => {
      group({ layout: AuthLayout, auth: 'guest' }, () => {
        registerGuestRoutes();
      });

      group({ layout: AuthLayout }, () => {
        registerLogoutRoute();
      });

      group({ layout: AppLayout, auth: true }, () => {
        registerAppRoutes();
      });

      fallback(NotFoundPage);
    });
  },
  {
    auth: {
      resolve: resolveAdminSession,
      loginPath: (context) => `/auth?next=${encodeURIComponent(context.href)}`,
      guestRedirectTo: '/app',
    },
  }
);
