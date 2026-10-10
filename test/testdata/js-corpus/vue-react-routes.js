// Vue router nested routes (relative and absolute children), react-router
// JSX, and programmatic navigation.
const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: "/users",
      component: UsersLayout,
      children: [
        { path: "", component: UserList },
        { path: ":id/edit", component: UserEdit },
        { path: "/user-search", component: UserSearch },
      ],
    },
  ],
});

function App() {
  return (
    <Routes>
      <Route path="/orders" element={<Orders />} />
      <Link to="/orders/new">New</Link>
    </Routes>
  );
}

history.pushState({}, "", "/checkout/step-1");
router.push("/checkout/step-2");
