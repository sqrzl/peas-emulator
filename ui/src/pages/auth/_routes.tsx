import { route } from "@askrjs/askr/router";
import LoginPage from "./login";
import LogoutPage from "./logout";

export function registerGuestRoutes(): void {
  route("/", LoginPage);
  route("/login", LoginPage);
  route("/auth", LoginPage);
  route("/auth/login", LoginPage);
}

export function registerLogoutRoute(): void {
  route("/logout", LogoutPage);
  route("/auth/logout", LogoutPage);
}

export function registerAuthRoutes(): void {
  registerGuestRoutes();
  registerLogoutRoute();
}
