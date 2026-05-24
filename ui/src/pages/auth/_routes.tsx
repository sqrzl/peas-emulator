import { route } from '@askrjs/askr/router';
import LoginPage from './login';
import LogoutPage from './logout';

export function registerAuthRoutes(): void {
  route('/', LoginPage);
  route('/auth', LoginPage);
  route('/auth/login', LoginPage);
  route('/auth/logout', LogoutPage);
}
