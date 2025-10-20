const BILLING_KEY = 'vulnerai.billing';
const STRIPE_CHECKOUT_URL = 'https://checkout.stripe.com/c/pay/REPLACE_ME';

const $  = (s,el=document)=>el.querySelector(s);
const $$ = (s,el=document)=>[...el.querySelectorAll(s)];

let billing = (()=>{
  const u=new URL(window.location.href);
  const q=(u.searchParams.get('billing')||'').toLowerCase();
  const ls=(localStorage.getItem(BILLING_KEY)||'').toLowerCase();
  if(q==='monthly'||q==='yearly')return q;
  if(ls==='monthly'||ls==='yearly')return ls;
  return'monthly';
})();

function formatEuro(n){return`€${n.toFixed(2)}`;}
function recalcSummary(){
  const isMonthly=billing==='monthly';
  const base=isMonthly?9.99:95.88/12, vat=base*0.23, tot=base+vat;
  $('#sum-plan').textContent=isMonthly?'Premium — Monthly':'Premium — Yearly';
  $('#sum-price').textContent=`${formatEuro(isMonthly?9.99:7.99)} / mo`;
  $('#sum-billed').textContent=isMonthly?'Billed monthly':'Billed €95.88/year';
  $('#sum-vat').textContent=formatEuro(vat);
  $('#sum-total').textContent=formatEuro(tot);
  $('#btn-monthly').classList.toggle('active',isMonthly);
  $('#btn-yearly').classList.toggle('active',!isMonthly);
}

function setBilling(b){billing=b;localStorage.setItem(BILLING_KEY,b);recalcSummary();}
function validateForm(){
  const n=$('#name').value.trim(),e=$('#email').value.trim(),a=$('#agree').checked;
  if(!n)return alert('Please enter your full name.'),false;
  if(!/\S+@\S+\.\S+/.test(e))return alert('Enter a valid email.'),false;
  if(!a)return alert('You must accept the Terms and Privacy Policy.'),false;
  return true;
}
function goStripe(){
  if(!STRIPE_CHECKOUT_URL.includes('http'))return alert('Insert your Stripe URL.'),0;
  const u=new URL(STRIPE_CHECKOUT_URL);u.searchParams.set('billing',billing);
  window.location.href=u;
}

/* ===== CAMPOS DINÂMICOS ===== */
function renderPaymentFields(m){
  const w=$('#payment-fields');w.innerHTML='';
  if(m==='card'){
    w.innerHTML=`
      <div class="field"><label>Cardholder name</label><input id="card-name" placeholder="Name on card" required></div>
      <div class="field"><label>Card number</label><input id="card-number" maxlength="19" placeholder="1234 5678 9012 3456" required></div>
      <div class="row">
        <div class="col field"><label>Expiry</label><input id="card-exp" maxlength="5" placeholder="MM/YY" required></div>
        <div class="col field"><label>CVC</label><input id="card-cvc" maxlength="4" placeholder="123" required></div>
      </div>`;
  }else if(m==='paypal'){
    w.innerHTML=`<div class="field"><label>PayPal Email</label><input type="email" id="paypal-email" placeholder="you@paypal.com" required></div>`;
  }else if(m==='apple'){
    w.innerHTML=`<p>You’ll be redirected to <strong>Apple Pay</strong> for authorization.</p>`;
  }else if(m==='google'){
    w.innerHTML=`<p>You’ll be redirected to <strong>Google Pay</strong> for authorization.</p>`;
  }
  w.classList.toggle('active',!!w.innerHTML.trim());
}

/* ===== MODAL ===== */
const LEGAL_DOCS={
  terms:`<h1>Terms of Service</h1><p>These Terms govern your use of VulnerAI...</p>`,
  privacy:`<h1>Privacy Policy</h1><p>We respect your privacy...</p>`
};
function openLegalModal(k){
  const m=$('#legal-modal'),b=$('#legal-body'),t=$('#legal-title');
  t.textContent=k==='privacy'?'Privacy Policy':'Terms of Service';
  fetch(k+'.html').then(r=>r.ok?r.text():Promise.reject()).then(h=>{
    const tmp=document.createElement('div');tmp.innerHTML=h;
    b.innerHTML=tmp.querySelector('main')?.innerHTML||h;
  }).catch(()=>b.innerHTML=LEGAL_DOCS[k]).finally(()=>{
    m.setAttribute('aria-hidden','false');document.body.style.overflow='hidden';
  });
}
function closeLegal(){ $('#legal-modal').setAttribute('aria-hidden','true');document.body.style.overflow=''; }

/* ===== EVENTS ===== */
function wireEvents(){
  $('#btn-back').onclick=()=>history.length>1?history.back():location.href='pricing.html';
  $('#btn-monthly').onclick=()=>setBilling('monthly');
  $('#btn-yearly').onclick=()=>setBilling('yearly');
  $('#bill-form').onsubmit=e=>{e.preventDefault();if(!validateForm())return;goStripe();};
  $('#btn-cancel').onclick=()=>location.href='pricing.html?billing='+billing;
  $$('input[name="pm"]').forEach(r=>r.onchange=()=>renderPaymentFields(r.value));
  renderPaymentFields('card');
  document.addEventListener('click',e=>{
    const a=e.target.closest('a[data-doc]');if(!a)return;
    e.preventDefault();openLegalModal(a.dataset.doc);
  });
  $('#legal-modal').addEventListener('click',e=>{
    if(e.target.hasAttribute('data-close')||e.target.classList.contains('modal-close'))closeLegal();
  });
  document.addEventListener('keydown',e=>{if(e.key==='Escape')closeLegal();});
}

document.addEventListener('DOMContentLoaded',()=>{recalcSummary();wireEvents();});


(function () {
  // ====== MÉTODOS: highlight + mostrar painel ======
  const methodsWrap = document.querySelector('.pay-methods');
  const items = [...document.querySelectorAll('.pm-item')];
  const radios = [...document.querySelectorAll('input[type="radio"][name="pm"]')];
  const panels = [...document.querySelectorAll('.pm-panels .panel')];

  function showPanel(method) {
    panels.forEach(p => p.classList.toggle('hidden', p.dataset.method !== method));
  }
  function setActiveByRadio(radio) {
    items.forEach(lbl => lbl.classList.remove('active'));
    const label = radio.closest('.pm-item');
    label?.classList.add('active');
    showPanel(radio.value);
  }

  radios.forEach(r => {
    r.addEventListener('change', () => setActiveByRadio(r));
    const label = r.closest('.pm-item');
    label?.addEventListener('click', (e) => {
      if (e.target.tagName !== 'INPUT') {
        r.checked = true;
        r.dispatchEvent(new Event('change', { bubbles: true }));
      }
    });
  });

  const initiallyChecked = radios.find(r => r.checked) || radios[0];
  if (initiallyChecked) setActiveByRadio(initiallyChecked);

  // ====== MODAL: Terms & Privacy ======
  const modal = document.getElementById('modal-legal');
  const body  = document.getElementById('modal-legal-body');
  const title = document.getElementById('modal-legal-title');
  function openModal(kind){
    title.textContent = kind === 'terms' ? 'Terms of Service' : 'Privacy Policy';
    body.innerHTML = kind === 'terms'
      ? `<h4>1. Use of Service</h4>
         <p>You agree to use VulnerAI responsibly and comply with applicable laws.</p>
         <h4>2. Billing</h4>
         <p>Subscriptions renew automatically until cancelled from your account.</p>
         <h4>3. Fair Usage</h4>
         <p>Scanning is limited to targets you own or are authorized to test.</p>`
      : `<h4>Data we collect</h4>
         <p>Account email, billing data and scan metadata. We don’t sell your data.</p>
         <h4>How we use it</h4>
         <p>To provide the service, billing, support and improve features.</p>
         <h4>Your rights</h4>
         <p>Export or delete your data anytime by contacting support.</p>`;
    modal.classList.remove('hidden');
    modal.setAttribute('aria-hidden', 'false');
  }
  function closeModal(){
    modal.classList.add('hidden');
    modal.setAttribute('aria-hidden', 'true');
  }
  document.getElementById('lnk-terms')?.addEventListener('click', (e)=>{ e.preventDefault(); openModal('terms'); });
  document.getElementById('lnk-privacy')?.addEventListener('click', (e)=>{ e.preventDefault(); openModal('privacy'); });
  modal?.addEventListener('click', (e)=>{ if(e.target.hasAttribute('data-close') || e.target.classList.contains('modal__close')) closeModal(); });
  document.addEventListener('keydown', (e)=>{ if(e.key === 'Escape') closeModal(); });

  // ====== VALIDAÇÃO DE CARTÃO (simples + Luhn) ======
  const inpName = document.getElementById('cc-name');
  const inpNum  = document.getElementById('cc-number');
  const inpExp  = document.getElementById('cc-exp');
  const inpCvc  = document.getElementById('cc-cvc');

  function onlyDigits(s){ return (s||'').replace(/\D+/g,''); }

  // máscara leve para número de cartão
  inpNum?.addEventListener('input', ()=>{
    const d = onlyDigits(inpNum.value).slice(0,19);
    inpNum.value = d.replace(/(.{4})/g,'$1 ').trim();
  });

  // máscara de validade
  inpExp?.addEventListener('input', ()=>{
    let d = onlyDigits(inpExp.value).slice(0,4);
    if(d.length >= 3) d = d.slice(0,2) + '/' + d.slice(2);
    inpExp.value = d;
  });

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

  function validateCard(){
    const nameOk = (inpName.value || '').trim().length >= 3;
    const numOk  = luhnCheck(inpNum.value) && onlyDigits(inpNum.value).length >= 13;
    const expOk  = (()=> {
      const m = /^(\d{2})\/(\d{2})$/.exec(inpExp.value);
      if(!m) return false;
      const mm = parseInt(m[1],10), yy = parseInt(m[2],10);
      if(mm<1 || mm>12) return false;
      // validade mínima = mês atual
      const now = new Date();
      const yNow = now.getFullYear() % 100;
      const mNow = now.getMonth()+1;
      if(yy < yNow) return false;
      if(yy === yNow && mm < mNow) return false;
      return true;
    })();
    const cvcOk  = /^[0-9]{3,4}$/.test(onlyDigits(inpCvc.value));

    const problems = [];
    if(!nameOk) problems.push('Cardholder name');
    if(!numOk)  problems.push('Card number');
    if(!expOk)  problems.push('Expiry');
    if(!cvcOk)  problems.push('CVC');

    return { ok: nameOk && numOk && expOk && cvcOk, problems };
  }

  // ====== SUBMIT (demo) ======
  const btnPay = document.getElementById('btn-checkout');
  const agree  = document.getElementById('agree');
  const toast  = document.getElementById('toast');

  btnPay?.addEventListener('click', (e)=>{
    e.preventDefault();

    const chosen = (radios.find(r => r.checked) || {}).value || 'card';
    if(!agree?.checked){
      alert('Please agree to the Terms and Privacy Policy.');
      return;
    }

    if(chosen === 'card'){
      const res = validateCard();
      if(!res.ok){
        alert('Please check: ' + res.problems.join(', ') + '.');
        return;
      }
      // Aqui integrarias Stripe/checkout do teu backend
      showToast('Card payment submitted (demo).');
    }

    if(chosen === 'apple'){
      showToast('Apple Pay flow triggered (demo).');
    }
    if(chosen === 'google'){
      showToast('Google Pay flow triggered (demo).');
    }
    if(chosen === 'paypal'){
      showToast('Redirecting to PayPal (demo).');
    }
  });

  function showToast(msg){
    if(!toast) return;
    toast.textContent = msg;
    toast.classList.add('show');
    setTimeout(()=> toast.classList.remove('show'), 2200);
  }
})();


function validateCard(){
  const nameOk = ($('#cc-name').value || '').trim().length >= 2;
  const numOk  = (($('#cc-number').value || '').replace(/\D+/g,'').length >= 12);
  const expOk  = (()=> {
    const m = /^(\d{2})\/(\d{2})$/.exec($('#cc-exp').value || '');
    if(!m) return false;
    const mm = +m[1], yy = +m[2];
    if(mm < 1 || mm > 12) return false;
    const now = new Date(); const yNow = now.getFullYear() % 100; const mNow = now.getMonth()+1;
    if(yy < yNow) return false;
    if(yy === yNow && mm < mNow) return false;
    return true;
  })();
  const cvcOk  = (/^\d{3,4}$/).test(($('#cc-cvc').value || '').replace(/\D+/g,''));
  return { ok: nameOk && numOk && expOk && cvcOk, problems: [] };
}
