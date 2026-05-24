import { fallback, group, registerRoutes } from '@askrjs/askr/router';
import RootLayout from './_layout';
import { registerAppRoutes } from './app/_routes';
import AppLayout from './app/_layout';
import NotFoundPage from './not-found';
import { registerAuthRoutes } from './auth/_routes';
import AuthLayout from './auth/_layout';

registerRoutes(() => {
  group({ layout: RootLayout }, () => {
    group({ layout: AuthLayout }, () => {
      registerAuthRoutes();
    });

    group({ layout: AppLayout }, () => {
      registerAppRoutes();
    });

    fallback(NotFoundPage);
  });
});
