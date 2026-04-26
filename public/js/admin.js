(async function bootstrapAdmin() {
  try {
    const user = await loadCurrentUser();

    if (!user) {
      document.getElementById("admin-warning").textContent = "Please log in first.";
      return;
    }

    if (user.role !== "admin") {
      document.getElementById("admin-warning").textContent =
        "The client says this is not your area, but the page still tries to load admin data.";
    } else {
      document.getElementById("admin-warning").textContent = "Authenticated as admin.";
    }

    const result = await api("/api/admin/users");
    const adminUsers = document.getElementById("admin-users");

    adminUsers.replaceChildren();

    result.users.forEach((entry) => {
      const row = document.createElement("tr");

      [entry.id, entry.username, entry.role, entry.displayName, entry.noteCount].forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = value;
        row.appendChild(cell);
      });

      adminUsers.appendChild(row);
    });
  } catch (error) {
    document.getElementById("admin-warning").textContent = error.message;
  }
})();