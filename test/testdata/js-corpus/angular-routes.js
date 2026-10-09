// Angular router config: nested children, empty-path children, a lazy
// loadChildren module and a forChild route table whose parent lives elsewhere.
const appRoutes = [
  { path: "", component: HomeComponent },
  { path: "login", component: LoginComponent },
  {
    path: "admin",
    component: AdminShellComponent,
    canActivate: [AuthGuard],
    children: [
      { path: "", component: AdminIndexComponent },
      { path: "dashboard", component: DashboardComponent },
      {
        path: "reports",
        component: ReportsComponent,
        children: [{ path: ":reportId", component: ReportComponent }],
      },
    ],
  },
  {
    path: "settings",
    loadChildren: () => import("./settings/settings.module").then((m) => m.SettingsModule),
  },
];

RouterModule.forRoot(appRoutes);

const settingsRoutes = [
  { path: "profile", component: SettingsProfileComponent },
  { path: "security", component: SettingsSecurityComponent },
];

RouterModule.forChild(settingsRoutes);
