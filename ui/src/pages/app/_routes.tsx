import { route } from '@askrjs/askr/router';
import BucketsPage from './buckets';
import AdminHomePage from './admin-home';
import SettingsPage from './settings';

export function registerAppRoutes(): void {
  route('/app', AdminHomePage);
  route('/app/buckets', BucketsPage);
  route('/app/settings', SettingsPage);
}
