import { route } from '@askrjs/askr/router';
import BucketInventoryPage from './agent-runs';
import AdminHomePage from './admin-home';
import SettingsPage from './settings';

export function registerAppRoutes(): void {
  route('/app', AdminHomePage);
  route('/app/buckets', BucketInventoryPage);
  route('/app/settings', SettingsPage);
}
