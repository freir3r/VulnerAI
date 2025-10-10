// Abrir modal de Termos & Privacidade
const modalLinks = document.querySelectorAll('.link-modal');
const body = document.body;

modalLinks.forEach(a => {
  a.addEventListener('click', (e) => {
    e.preventDefault();
    const target = document.querySelector(a.dataset.target || '#terms-modal');
    openModal(target);
  });
});

function openModal(el){
  if(!el) return;
  el.setAttribute('aria-hidden', 'false');
  const dialog = el.querySelector('.modal-dialog');
  // foco inicial
  setTimeout(() => dialog.focus(), 0);

  // fechar com ESC
  el._escHandler = (ev) => { if(ev.key === 'Escape') closeModal(el); };
  document.addEventListener('keydown', el._escHandler);
}

function closeModal(el){
  if(!el) return;
  el.setAttribute('aria-hidden', 'true');
  if(el._escHandler){
    document.removeEventListener('keydown', el._escHandler);
    el._escHandler = null;
  }
}

// Clicar no backdrop ou no botão fechar fecha o modal
document.addEventListener('click', (e) => {
  if(e.target.matches('[data-close]')){
    const modal = e.target.closest('.modal');
    closeModal(modal);
  }
});
