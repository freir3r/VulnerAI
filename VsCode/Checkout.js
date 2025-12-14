
// frontend/checkout.js (completo e actualizado)
// Principais alterações:
// 1) Melhora de debug (logs no console) para confirmar billing enviado.
// 2) Suporte opcional para enviar priceId directamente se as variáveis globais PRICE_MONTHLY / PRICE_YEARLY estiverem definidas no HTML.
// 3) Correção de cálculo/display do resumo para usar os valores calculados.
// 4) Protecções contra double-submit e mensagens de erro mais claras.
// 5) Pequenas limpezas e comentários.

const fs = {}; // placeholder (não usado) — mantido para compatibilidade com ambientes que esperem um objecto global

// util helpers
const $  = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];

// --- CONFIGURAÇÃO: endpoint do teu backend ---
const BILLING_KEY = 'vulnerai.billing';
const API_BASE = 'http://127.0.0.1:4242'; // ajusta se o teu backend usar outro host/porta

/* ============================
   FUNÇÕES BÁSICAS
   ============================ */

// recalcula totais e atualiza UI
function recalcSummary() {
  let billing = (localStorage.getItem(BILLING_KEY) || 'monthly').toLowerCase();
  const isMonthly = billing === 'monthly';

  // valores base — ajusta se mudares preços reais
  const monthlyPrice = 9.99;
  const yearlyPriceTotal = 95.88; // preço anual total
  const monthlyEquivalent = yearlyPriceTotal / 12; // se mostrares equivalente por mês

  const base = isMonthly ? monthlyPrice : monthlyEquivalent;
  const vat = base * 0.23;
  const tot = base + vat;

  $('#sum-plan').textContent = isMonthly ? 'Premium — Monthly' : 'Premium — Yearly';
  // mostra o preço correcto por mês (ou equivalente)
  $('#sum-price').textContent = isMonthly ? `${formatEuro(monthlyPrice)} / mo` : `${formatEuro(monthlyEquivalent)} / mo`;
  $('#sum-billed').textContent = isMonthly ? 'Billed monthly' : `Billed yearly (${formatEuro(yearlyPriceTotal)}/yr, save 20%)`;
  $('#sum-vat').textContent = formatEuro(vat);
  $('#sum-total').textContent = formatEuro(tot);

  $('#btn-monthly')?.classList.toggle('active', isMonthly);
  $('#btn-yearly')?.classList.toggle('active', !isMonthly);
}

function formatEuro(n){ return `€${Number(n || 0).toFixed(2)}`; }

/* ===== Função que chama o backend e redireciona para o Stripe Checkout ===== */
let _submitting = false;
async function goStripe() {
  if (_submitting) {
    console.warn('Já a submeter — aguarda por favor.');
    return;
  }

  // valida formulário (usa validateForm presente mais abaixo)
  if (!validateForm()) return;

  const email = ($('#email')?.value || '').trim() || undefined;
  const billingChoice = (localStorage.getItem(BILLING_KEY) || 'monthly').toLowerCase();

  // Se o frontend tiver sido configurado com price IDs (na página HTML),
  // preferimos enviar priceId diretamente. Isto evita confusões com env vars trocadas.
  const sendPriceDirectly = !!(window.PRICE_MONTHLY && window.PRICE_YEARLY);
  const payload = sendPriceDirectly ? { priceId: billingChoice === 'yearly' ? window.PRICE_YEARLY : window.PRICE_MONTHLY, customerEmail: email } 
                                     : { billing: billingChoice, customerEmail: email };

  try {
    _submitting = true;
    // desativar botão
    const payBtn = $('#btn-pay');
    if (payBtn) { payBtn.disabled = true; payBtn.textContent = 'Redirecting...'; }

    console.log('Criando sessão de checkout — payload:', payload);

    const resp = await fetch(`${API_BASE}/create-checkout-session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await resp.json().catch(() => null);

    if (!resp.ok) {
      console.error('Backend error:', data);
      alert(data?.error || 'Erro ao criar sessão de checkout (ver console).');
      if (payBtn) { payBtn.disabled = false; payBtn.textContent = 'Pay now'; }
      _submitting = false;
      return;
    }

    if (data?.url) {
      console.info('Redireccionando para Stripe Checkout:', data.url);
      window.location.href = data.url;
      return;
    }

    alert('Resposta inesperada do servidor ao criar a sessão.');
    if (payBtn) { payBtn.disabled = false; payBtn.textContent = 'Pay now'; }
  } catch (err) {
    console.error('Erro de rede ao chamar o backend:', err);
    alert('Erro de rede. Confirma que o backend está a correr em ' + API_BASE);
    const payBtn = $('#btn-pay');
    if (payBtn) { payBtn.disabled = false; payBtn.textContent = 'Pay now'; }
  } finally {
    _submitting = false;
  }
}
// expõe para a console (útil para debug)
window.goStripe = goStripe;

/* ===== CAMPOS DINÂMICOS ===== */
function renderPaymentFields(m){
  const w = $('#payment-fields'); if(!w) return;
  w.innerHTML = '';
  if (m === 'card') {
    w.innerHTML = `
      <div class="field"><label>Cardholder name</label><input id="card-name" placeholder="Name on card" required></div>
      <div class="field"><label>Card number</label><input id="card-number" maxlength="19" placeholder="1234 5678 9012 3456" required></div>
      <div class="row">
        <div class="col field"><label>Expiry</label><input id="card-exp" maxlength="5" placeholder="MM/YY" required></div>
        <div class="col field"><label>CVC</label><input id="card-cvc" maxlength="4" placeholder="123" required></div>
      </div>`;
  } else if (m === 'paypal') {
    w.innerHTML = `<div class="field"><label>PayPal Email</label><input type="email" id="paypal-email" placeholder="you@paypal.com" required></div>`;
  } else if (m === 'apple') {
    w.innerHTML = `<p>You’ll be redirected to <strong>Apple Pay</strong> for authorization.</p>`;
  } else if (m === 'google') {
    w.innerHTML = `<p>You’ll be redirected to <strong>Google Pay</strong> for authorization.</p>`;
  }
  w.classList.toggle('active', !!w.innerHTML.trim());
}

/* ===== MODAL ===== */
const LEGAL_DOCS = {
  terms: `
    <h2>Terms of Service</h2>
    <p>Welcome to <strong>VulnerAI</strong>. By using our platform, you agree to comply with these Terms of Service. Please read them carefully before subscribing or making any payment.</p>

    <h3>1. Use of Service</h3>
    <p>You agree to use VulnerAI only for legal and authorized security assessments. Scanning systems without permission is strictly prohibited and may result in account suspension or legal action.</p>

    <h3>2. Accounts & Subscriptions</h3>
    <p>Premium features require an active subscription. Subscriptions renew automatically unless cancelled before the renewal date.</p>

    <h3>3. Payments & Refunds</h3>
    <p>All payments are securely processed through third-party payment providers. Charges are non-refundable after a scan or report has been executed. Billing issues must be reported within 7 days.</p>

    <h3>4. Data Security</h3>
    <p>We do not store payment information. Scan data and account information are handled according to our <a href="#" data-doc="privacy">Privacy Policy</a>.</p>

    <h3>5. Limitation of Liability</h3>
    <p>Although we strive for accuracy, VulnerAI does not guarantee that all vulnerabilities are detected. You assume full responsibility for how scan results are used.</p>

    <h3>6. Termination</h3>
    <p>Your access may be suspended if suspicious activity or Terms violations are detected. You may cancel your subscription at any time.</p>

    <h3>7. Contact</h3>
    <p>For questions regarding these Terms, contact <a href="mailto:support@vulnerai.com">support@vulnerai.com</a>.</p>

    <p style="margin-top:14px; font-size:.9rem; color:#999;">Last updated: October 2025</p>
  `,

  privacy: `
    <h2>Privacy Policy</h2>
    <p>Your privacy is important to us. This policy explains how we collect, store, and protect your personal data when using <strong>VulnerAI</strong>.</p>

    <h3>1. Information We Collect</h3>
    <p>We collect only essential data for account creation, billing, and security scans. Payment details are handled by certified payment processors and never stored on our servers.</p>

    <h3>2. How We Use Data</h3>
    <p>Your information is used to provide services, improve platform performance, and communicate important updates. We do not sell or share your data.</p>

    <h3>3. Cookies</h3>
    <p>Cookies help maintain login sessions and dashboard personalization. You may disable cookies, but some features may stop working.</p>

    <h3>4. Data Protection</h3>
    <p>All communication is encrypted via TLS. Access to user data is restricted and logged under internal security procedures.</p>

    <h3>5. User Rights</h3>
    <p>You may request access, correction, or deletion of your data at any time.</p>

    <h3>6. Contact</h3>
    <p>Privacy inquiries may be sent to <a href="mailto:privacy@vulnerai.com">privacy@vulnerai.com</a>.</p>

    <p style="margin-top:14px; font-size:.9rem; color:#999;">Last updated: October 2025</p>
  `
};

function openLegalModal(k){
  const m = $('#legal-modal'), b = $('#legal-body'), t = $('#legal-title');
  if(!m) return;
  t.textContent = k === 'privacy' ? 'Privacy Policy' : 'Terms of Service';
  // fallback simples (não depende de fetch)
  b.innerHTML = LEGAL_DOCS[k] || '';
  m.setAttribute('aria-hidden','false'); document.body.style.overflow = 'hidden';
}
function closeLegal(){ $('#legal-modal')?.setAttribute('aria-hidden','true'); document.body.style.overflow=''; }

/* ===== VALIDAÇÃO E UTILS DE CARTÃO ===== */
function onlyDigits(s){ return (s||'').replace(/\D+/g,''); }

function luhnCheck(num){
  const s = onlyDigits(num);
  if(!s) return false;
  let sum = 0, dbl = false;
  for(let i = s.length - 1; i >= 0; i--){
    let n = parseInt(s[i],10);
    if(dbl){ n*=2; if(n>9) n-=9; }
    sum += n;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

function validateCardFields(){
  const inpName = document.getElementById('cc-name') || document.getElementById('card-name');
  const inpNum  = document.getElementById('cc-number') || document.getElementById('card-number');
  const inpExp  = document.getElementById('cc-exp') || document.getElementById('card-exp');
  const inpCvc  = document.getElementById('cc-cvc') || document.getElementById('card-cvc');

  const nameOk = (inpName?.value || '').trim().length >= 3;
  const numOk  = luhnCheck(inpNum?.value || '') && onlyDigits(inpNum?.value || '').length >= 13;
  const expOk  = (()=> {
    const m = /^(\d{2})\/(\d{2})$/.exec(inpExp?.value || '');
    if (!m) return false;
    const mm = parseInt(m[1],10), yy = parseInt(m[2],10);
    if (mm < 1 || mm > 12) return false;
    const now = new Date(); const yNow = now.getFullYear() % 100; const mNow = now.getMonth() + 1;
    if (yy < yNow) return false;
    if (yy === yNow && mm < mNow) return false;
    return true;
  })();
  const cvcOk  = /^[0-9]{3,4}$/.test(onlyDigits(inpCvc?.value || ''));

  const problems = [];
  if (!nameOk) problems.push('Cardholder name');
  if (!numOk)  problems.push('Card number');
  if (!expOk)  problems.push('Expiry');
  if (!cvcOk)  problems.push('CVC');

  return { ok: nameOk && numOk && expOk && cvcOk, problems };
}

/* ===== FORM VALIDATION (billing form) ===== */
function validateForm(){
  const n = $('#name')?.value.trim();
  const e = $('#email')?.value.trim();
  const a = $('#agree')?.checked;

  if(!n){ alert('Please enter your full name.'); return false; }
  if(!/\S+@\S+\.\S+/.test(e)){ alert('Enter a valid email.'); return false; }
  if(!a){ alert('You must accept the Terms and Privacy Policy.'); return false; }
  return true;
}

/* ===== UI: toasts ===== */
function showToast(msg){
  const toast = $('#toast');
  if(!toast) return;
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(()=> toast.classList.remove('show'), 2200);
}

/* ===== Events wiring ===== */
function wireEvents(){
  // back
  $('#btn-back')?.addEventListener('click', ()=> history.length > 1 ? history.back() : location.href = 'pricing.html');

  // billing toggles
  $('#btn-monthly')?.addEventListener('click', ()=> { localStorage.setItem(BILLING_KEY,'monthly'); recalcSummary(); });
  $('#btn-yearly')?.addEventListener('click', ()=> { localStorage.setItem(BILLING_KEY,'yearly'); recalcSummary(); });

  // form submit (guarantee)
  const form = $('#bill-form');
  if(form){
    form.addEventListener('submit', e => {
      e.preventDefault();
      if(!validateForm()) return;
      goStripe();
    });
  }

  // direct button listener (force)
  const btnPay = $('#btn-pay') || $('#btn-checkout');
  if(btnPay){
    btnPay.addEventListener('click', e => {
      e.preventDefault();
      if(!validateForm()) return;
      goStripe();
    });
    console.log('Pay button listener attached');
  } else {
    console.warn('Pay button not found (#btn-pay or #btn-checkout)');
  }

  // cancel
  $('#btn-cancel')?.addEventListener('click', ()=> location.href = 'pricing.html?billing=' + (localStorage.getItem(BILLING_KEY) || 'monthly'));

  // payment method change
  $$('input[name="pm"]').forEach(r => r.addEventListener('change', ()=> renderPaymentFields(r.value)));
  renderPaymentFields('card');

  // modal links
  document.addEventListener('click', e => {
    const a = e.target.closest('[data-doc]');
    if(!a) return;
    e.preventDefault();
    openLegalModal(a.dataset.doc);
  });

  // modal close
  $('#legal-modal')?.addEventListener('click', e => {
    if(e.target.hasAttribute('data-close') || e.target.classList.contains('modal-close')) closeLegal();
  });

  // keyboard
  document.addEventListener('keydown', e => { if(e.key === 'Escape') closeLegal(); });

  // card inputs masking (if present)
  const inpNum = document.getElementById('cc-number') || document.getElementById('card-number');
  const inpExp = document.getElementById('cc-exp') || document.getElementById('card-exp');
  const inpCvc = document.getElementById('cc-cvc') || document.getElementById('card-cvc');

  if(inpNum){
    inpNum.addEventListener('input', ()=> {
      const d = onlyDigits(inpNum.value).slice(0,19);
      inpNum.value = d.replace(/(.{4})/g,'$1 ').trim();
    });
  }
  if(inpExp){
    inpExp.addEventListener('input', ()=> {
      let d = onlyDigits(inpExp.value).slice(0,4);
      if(d.length >= 3) d = d.slice(0,2) + '/' + d.slice(2);
      inpExp.value = d;
    });
  }
}

/* ===== DOMContentLoaded: inicia tudo ===== */
document.addEventListener('DOMContentLoaded', () => {
  try {
    // garante que existe um valor inicial
    if(!localStorage.getItem(BILLING_KEY)) localStorage.setItem(BILLING_KEY, 'monthly');
    recalcSummary();
    wireEvents();
    // expõe para debug no console
    window.goStripe = goStripe;
    console.log('checkout.js initialised — API_BASE=' + API_BASE + ' — PRICE direct support=' + (!!(window.PRICE_MONTHLY && window.PRICE_YEARLY)));
  } catch (err) {
    console.error('Error during init:', err);
  }
});
