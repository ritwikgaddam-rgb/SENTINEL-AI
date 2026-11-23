const select = document.querySelector("#theme");
const logo = document.querySelector("#logo");
const status = document.querySelector("#status");

async function applyTheme(value) {
  const theme = value === "orange" ? "orange" : "navy";
  select.value = theme;
  document.documentElement.dataset.theme = theme;
  logo.src = `logos/${theme}.svg`;
  localStorage.setItem("sentinelai-theme", theme);

  try {
    await chrome.action.setIcon({
      path: {
        16: `icons/${theme}/16.png`,
        24: `icons/${theme}/24.png`,
        32: `icons/${theme}/32.png`,
      },
    });
    status.textContent = "";
  } catch {
    status.textContent = "Chrome could not update the toolbar icon.";
  }
}

select.addEventListener("change", () => void applyTheme(select.value));
void applyTheme(localStorage.getItem("sentinelai-theme"));
