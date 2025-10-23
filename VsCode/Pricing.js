// ===== Pricing JS =====

const BILLING_KEY = 'vulnerai.billing';

// helpers
const $  = (s, el=document) => el.querySelector(s);
const $$ = (s, el=document) => [...el.querySelectorAll(s)];

function getInitialBilling() {
  const url = new URL(window.location.href);
  const q = (url.searchParams.get('billing') || '').toLowerCase();
  const ls = (localStorage.getItem(BILLING_KEY) || '').toLowerCase();
  if (q === 'monthly' || q === 'yearly') return q;
  if (ls === 'monthly' || ls === 'yearly') return ls;
  return 'monthly';
}

let billing = getInitialBilling();

function applyBillingUI() {
  const btnM = $('#btn-monthly');
  const btnY = $('#btn-yearly');
  const amount = $('#price-amount');
  const note = $('#price-note');

  // toggle UI states
  btnM?.classList.toggle('active', billing === 'monthly');
  btnY?.classList.toggle('active', billing === 'yearly');
  btnM?.setAttribute('aria-selected', billing === 'monthly' ? 'true' : 'false');
  btnY?.setAttribute('aria-selected', billing === 'yearly'  ? 'true' : 'false');

  // preços e nota
  if (billing === 'monthly') {
    amount.textContent = '€9.99';
    note.textContent   = 'Billed monthly';
  } else {
    amount.textContent = '€7.99';
    note.textContent   = 'Billed €95.88/year';
  }
}

function goCheckout() {
  localStorage.setItem(BILLING_KEY, billing);
  const dest = `checkout.html?billing=${billing}`;
  window.location.href = dest;
}

function initFAQ() {
  $$('.faq-q').forEach(btn => {
    const answer = btn.nextElementSibling;
    if (!answer) return;

    // estado inicial
    btn.setAttribute('aria-expanded', 'false');
    answer.style.maxHeight = '0px';

    btn.addEventListener('click', () => {
      const expanded = btn.getAttribute('aria-expanded') === 'true';
      // fechar os outros (opcional)
      $$('.faq-q').forEach(b => {
        if (b !== btn) {
          b.setAttribute('aria-expanded', 'false');
          const a = b.nextElementSibling;
          if (a) a.style.maxHeight = '0px';
        }
      });

      btn.setAttribute('aria-expanded', expanded ? 'false' : 'true');
      if (expanded) {
        answer.style.maxHeight = '0px';
      } else {
        answer.style.maxHeight = answer.scrollHeight + 'px';
      }
    });
  });

  // re-calcular altura ao redimensionar (para animação ficar certa)
  window.addEventListener('resize', () => {
    $$('.faq-q').forEach(btn => {
      const answer = btn.nextElementSibling;
      if (!answer) return;
      if (btn.getAttribute('aria-expanded') === 'true') {
        answer.style.maxHeight = answer.scrollHeight + 'px';
      }
    });
  });
}

function wireEvents() {
  // back
  $('#btn-back')?.addEventListener('click', () => {
    if (window.history.length > 1) {
      history.back();
    } else {
      window.location.href = 'dashboard.html';
    }
  });

  // toggle billing
  $('#btn-monthly')?.addEventListener('click', () => {
    billing = 'monthly';
    localStorage.setItem(BILLING_KEY, billing);
    applyBillingUI();
    // opcional: refletir no URL
    const u = new URL(window.location.href);
    u.searchParams.set('billing', billing);
    window.history.replaceState({}, '', u);
  });

  $('#btn-yearly')?.addEventListener('click', () => {
    billing = 'yearly';
    localStorage.setItem(BILLING_KEY, billing);
    applyBillingUI();
    const u = new URL(window.location.href);
    u.searchParams.set('billing', billing);
    window.history.replaceState({}, '', u);
  });

  // CTAs
  $('#btn-get-premium')?.addEventListener('click', goCheckout);

  $('#btn-keep-free')?.addEventListener('click', () => {
    window.location.href = 'dashboard.html';
  });

  $('#btn-contact')?.addEventListener('click', () => {
    // troca por contact.html se tiveres
    window.location.href = 'mailto:sales@vulnerai.example?subject=VulnerAI%20Teams';
  });
}

document.addEventListener('DOMContentLoaded', () => {
  applyBillingUI();
  wireEvents();
  initFAQ();
});
