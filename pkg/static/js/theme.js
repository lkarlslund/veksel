(() => {
  const storageKey = 'veksel-color-theme';
  const order = ['auto', 'light', 'dark'];
  const choices = new Set(order);
  const controls = {
    auto: {icon: 'A', label: 'Theme: automatic'},
    light: {icon: '☀', label: 'Theme: light'},
    dark: {icon: '◐', label: 'Theme: dark'},
  };
  const systemDark = window.matchMedia('(prefers-color-scheme: dark)');

  const preference = () => {
    try {
      const stored = localStorage.getItem(storageKey);
      return choices.has(stored) ? stored : 'auto';
    } catch (_) {
      return 'auto';
    }
  };

  const syncControls = () => {
    const selected = document.documentElement.dataset.theme || preference();
    const button = document.querySelector('[data-theme-toggle]');
    if (!button) return;
    const current = controls[selected] || controls.auto;
    const next = order[(order.indexOf(selected) + 1) % order.length];
    button.dataset.themeMode = selected;
    button.querySelector('[data-theme-icon]').textContent = current.icon;
    button.setAttribute('aria-label', `${current.label}; switch to ${next}`);
    button.title = `${current.label} · click for ${next}`;
  };

  const apply = selected => {
    const theme = choices.has(selected) ? selected : 'auto';
    const resolved = theme === 'auto' ? (systemDark.matches ? 'dark' : 'light') : theme;
    const root = document.documentElement;
    root.dataset.theme = theme;
    root.dataset.colorScheme = resolved;
    root.style.colorScheme = resolved;
    syncControls();
    document.dispatchEvent(new CustomEvent('veksel:themechange', {detail: {theme, resolved}}));
  };

  const set = selected => {
    const theme = choices.has(selected) ? selected : 'auto';
    try {
      localStorage.setItem(storageKey, theme);
    } catch (_) {}
    apply(theme);
  };

  document.addEventListener('click', event => {
    const button = event.target.closest('[data-theme-toggle]');
    if (!button) return;
    const current = document.documentElement.dataset.theme || preference();
    set(order[(order.indexOf(current) + 1) % order.length]);
  });
  document.addEventListener('DOMContentLoaded', syncControls);
  if (systemDark.addEventListener) systemDark.addEventListener('change', () => {
    if (preference() === 'auto') apply('auto');
  });

  window.vekselTheme = {apply, set, preference, syncControls};
  apply(preference());
})();
