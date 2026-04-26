(function() {
  const menus = Array.from(document.querySelectorAll("[data-nav-menu]"));
  if (!menus.length) {
    return;
  }

  const closeMenu = (menu) => {
    const trigger = menu.querySelector("[data-nav-trigger]");
    const panel = menu.querySelector("[data-nav-panel]");
    if (!trigger || !panel) {
      return;
    }

    menu.dataset.open = "false";
    trigger.setAttribute("aria-expanded", "false");
    panel.hidden = true;
  };

  const openMenu = (menu) => {
    menus.forEach((candidate) => {
      if (candidate !== menu) {
        closeMenu(candidate);
      }
    });

    const trigger = menu.querySelector("[data-nav-trigger]");
    const panel = menu.querySelector("[data-nav-panel]");
    if (!trigger || !panel) {
      return;
    }

    menu.dataset.open = "true";
    trigger.setAttribute("aria-expanded", "true");
    panel.hidden = false;
  };

  menus.forEach((menu) => {
    const trigger = menu.querySelector("[data-nav-trigger]");
    const panel = menu.querySelector("[data-nav-panel]");
    if (!trigger || !panel) {
      return;
    }

    closeMenu(menu);

    trigger.addEventListener("click", function(event) {
      event.preventDefault();
      if (menu.dataset.open === "true") {
        closeMenu(menu);
      } else {
        openMenu(menu);
      }
    });

    panel.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", function() {
        closeMenu(menu);
      });
    });
  });

  document.addEventListener("click", function(event) {
    menus.forEach((menu) => {
      if (!menu.contains(event.target)) {
        closeMenu(menu);
      }
    });
  });

  document.addEventListener("keydown", function(event) {
    if (event.key !== "Escape") {
      return;
    }

    menus.forEach(closeMenu);
  });

  window.addEventListener("resize", function() {
    menus.forEach(closeMenu);
  });
})();
