document.addEventListener("DOMContentLoaded", () => {
  const activitiesList = document.getElementById("activities-list");
  const activitySelect = document.getElementById("activity");
  const signupForm = document.getElementById("signup-form");
  const signupContainer = document.getElementById("signup-container");
  const targetEmailGroup = document.getElementById("target-email-group");
  const messageDiv = document.getElementById("message");
  const sessionStatus = document.getElementById("session-status");
  const loginForm = document.getElementById("login-form");
  const registrationForm = document.getElementById("registration-form");
  const logoutButton = document.getElementById("logout-button");
  let currentUser = null;

  function showMessage(message, type) {
    messageDiv.textContent = message;
    messageDiv.className = `message ${type}`;
    setTimeout(() => messageDiv.classList.add("hidden"), 5000);
  }

  function renderSession() {
    const loggedIn = currentUser !== null;
    sessionStatus.textContent = loggedIn
      ? `Signed in as ${currentUser.name} (${currentUser.role})`
      : "Log in or create a student account to manage registrations.";
    loginForm.classList.toggle("hidden", loggedIn);
    registrationForm.classList.toggle("hidden", loggedIn);
    logoutButton.classList.toggle("hidden", !loggedIn);
    signupContainer.classList.toggle("hidden", !loggedIn);
    document.getElementById("email").required =
      loggedIn && currentUser.role === "admin";
    targetEmailGroup.classList.toggle(
      "hidden",
      !loggedIn || currentUser.role !== "admin"
    );
  }

  function handleExpiredSession(response) {
    if (response.status !== 401 || !currentUser) {
      return false;
    }
    currentUser = null;
    renderSession();
    showMessage("Your session expired. Please log in again.", "error");
    fetchActivities();
    return true;
  }

  async function fetchActivities() {
    try {
      const response = await fetch("/activities");
      if (!response.ok) {
        throw new Error("Failed to load activities");
      }
      const activities = await response.json();
      const selectedActivity = activitySelect.value;
      activitiesList.replaceChildren();
      activitySelect.replaceChildren(new Option("-- Select an activity --", ""));

      Object.entries(activities).forEach(([name, details]) => {
        const activityCard = document.createElement("div");
        activityCard.className = "activity-card";

        const title = document.createElement("h4");
        title.textContent = name;
        activityCard.appendChild(title);

        const description = document.createElement("p");
        description.textContent = details.description;
        activityCard.appendChild(description);

        const schedule = document.createElement("p");
        const scheduleLabel = document.createElement("strong");
        scheduleLabel.textContent = "Schedule: ";
        schedule.append(scheduleLabel, document.createTextNode(details.schedule));
        activityCard.appendChild(schedule);

        const availability = document.createElement("p");
        const availabilityLabel = document.createElement("strong");
        availabilityLabel.textContent = "Availability: ";
        availability.append(
          availabilityLabel,
          document.createTextNode(
            `${details.max_participants - details.participants.length} spots left`
          )
        );
        activityCard.appendChild(availability);

        const participantsContainer = document.createElement("div");
        participantsContainer.className = "participants-container";
        const participantsSection = document.createElement("div");
        participantsSection.className = "participants-section";

        if (details.participants.length > 0) {
          const participantsHeading = document.createElement("h5");
          participantsHeading.textContent = "Participants:";
          participantsSection.appendChild(participantsHeading);
          const participantsList = document.createElement("ul");
          participantsList.className = "participants-list";

          details.participants.forEach((email) => {
            const participantItem = document.createElement("li");
            const participantEmail = document.createElement("span");
            participantEmail.className = "participant-email";
            participantEmail.textContent = email;
            participantItem.appendChild(participantEmail);

            if (
              currentUser &&
              (currentUser.role === "admin" || currentUser.email === email)
            ) {
              const unregisterButton = document.createElement("button");
              unregisterButton.className = "delete-btn";
              unregisterButton.type = "button";
              unregisterButton.textContent = "Unregister";
              unregisterButton.dataset.activity = name;
              unregisterButton.dataset.email = email;
              unregisterButton.addEventListener("click", handleUnregister);
              participantItem.appendChild(unregisterButton);
            }
            participantsList.appendChild(participantItem);
          });
          participantsSection.appendChild(participantsList);
        } else {
          const emptyMessage = document.createElement("p");
          emptyMessage.textContent = "No participants yet";
          participantsSection.appendChild(emptyMessage);
        }

        participantsContainer.appendChild(participantsSection);
        activityCard.appendChild(participantsContainer);
        activitiesList.appendChild(activityCard);

        const option = new Option(name, name);
        activitySelect.appendChild(option);
      });

      if (activities[selectedActivity]) {
        activitySelect.value = selectedActivity;
      }
    } catch (error) {
      activitiesList.textContent =
        "Failed to load activities. Please try again later.";
      console.error("Error fetching activities:", error);
    }
  }

  async function handleUnregister(event) {
    const button = event.currentTarget;
    const activity = button.dataset.activity;
    const email = button.dataset.email;

    try {
      const response = await fetch(
        `/activities/${encodeURIComponent(
          activity
        )}/unregister?email=${encodeURIComponent(email)}`,
        { method: "DELETE" }
      );
      if (handleExpiredSession(response)) {
        return;
      }
      const result = await response.json();
      if (!response.ok) {
        showMessage(result.detail || "An error occurred", "error");
        return;
      }

      showMessage(result.message, "success");
      await fetchActivities();
    } catch (error) {
      showMessage("Failed to unregister. Please try again.", "error");
      console.error("Error unregistering:", error);
    }
  }

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const response = await fetch("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: document.getElementById("login-email").value,
          password: document.getElementById("login-password").value,
        }),
      });
      const result = await response.json();
      if (!response.ok) {
        showMessage(result.detail || "Unable to log in", "error");
        return;
      }
      currentUser = result;
      loginForm.reset();
      renderSession();
      await fetchActivities();
    } catch (error) {
      showMessage("Failed to log in. Please try again.", "error");
      console.error("Error logging in:", error);
    }
  });

  registrationForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const response = await fetch("/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: document.getElementById("student-name").value,
          grade: document.getElementById("student-grade").value,
          email: document.getElementById("registration-email").value,
          password: document.getElementById("registration-password").value,
        }),
      });
      const result = await response.json();
      if (!response.ok) {
        showMessage(result.detail || "Unable to create account", "error");
        return;
      }
      currentUser = result;
      registrationForm.reset();
      renderSession();
      await fetchActivities();
    } catch (error) {
      showMessage("Failed to create account. Please try again.", "error");
      console.error("Error registering:", error);
    }
  });

  logoutButton.addEventListener("click", async () => {
    try {
      const response = await fetch("/auth/logout", { method: "POST" });
      if (!response.ok) {
        throw new Error("Unable to log out");
      }
      currentUser = null;
      renderSession();
      await fetchActivities();
    } catch (error) {
      showMessage("Failed to log out. Please try again.", "error");
      console.error("Error logging out:", error);
    }
  });

  signupForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const activity = activitySelect.value;
    const emailInput = document.getElementById("email");
    const query = currentUser.role === "admin" && emailInput.value
      ? `?email=${encodeURIComponent(emailInput.value)}`
      : "";

    try {
      const response = await fetch(
        `/activities/${encodeURIComponent(activity)}/signup${query}`,
        { method: "POST" }
      );
      if (handleExpiredSession(response)) {
        return;
      }
      const result = await response.json();
      if (!response.ok) {
        showMessage(result.detail || "An error occurred", "error");
        return;
      }

      showMessage(result.message, "success");
      signupForm.reset();
      await fetchActivities();
    } catch (error) {
      showMessage("Failed to sign up. Please try again.", "error");
      console.error("Error signing up:", error);
    }
  });

  async function loadCurrentUser() {
    try {
      const response = await fetch("/auth/me");
      if (response.ok) {
        currentUser = await response.json();
      } else if (response.status !== 401) {
        throw new Error("Unable to check the current session");
      }
    } catch (error) {
      sessionStatus.textContent = "Unable to check your session.";
      console.error("Error checking session:", error);
    }
    renderSession();
    await fetchActivities();
  }

  renderSession();
  loadCurrentUser();
});
