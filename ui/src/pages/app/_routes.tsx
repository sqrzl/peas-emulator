import { route } from '@askrjs/askr/router';
import AgentRunsPage from './agent-runs';
import AdminHomePage from './admin-home';
import SettingsPage from './settings';

export function registerAppRoutes(): void {
  route('/app', AdminHomePage);
  route('/app/agents', AgentRunsPage);
  route('/app/settings', SettingsPage);
}
