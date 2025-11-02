// ====================================================================
// PARTE 1: CONFIGURAÇÃO DO FIREBASE E LÓGICA DE REGISTO
// ====================================================================

  import { initializeApp } from "https://www.gstatic.com/firebasejs/10.13.1/firebase-app.js";
  import { getAuth, createUserWithEmailAndPassword } from "https://www.gstatic.com/firebasejs/10.13.1/firebase-auth.js";
  import { getFirestore, doc, setDoc } from "https://www.gstatic.com/firebasejs/10.13.1/firebase-firestore.js";

// ** IMPORTANTE: SUBSTITUIR PELAS SUAS CHAVES DE CONFIGURAÇÃO DO FIREBASE **
const firebaseConfig = {
  apiKey: "AIzaSyBuaJdeJSHhn8zvOt3COp1fy987Zx4Da9k",
  authDomain: "vulnerai.firebaseapp.com",
  projectId: "vulnerai",
  storageBucket: "vulnerai.appspot.com",
  messagingSenderId: "576892753213",
  appId: "1:576892753213:web:bc90f8b14db38ac1d4a154",
  measurementId: "G-5733L55V7Y"
};


// Inicializar o Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// Selecionar o formulário e o botão
const form = document.querySelector('.form');
// Alteramos o 'onclick' no HTML para usar o evento de 'submit' ou 'click' do JS
const registerButton = document.querySelector('.btn-primary'); 

// Adicionar um gestor de eventos ao botão
registerButton.addEventListener('click', async (e) => {
    e.preventDefault(); // Impedir o reenvio do formulário HTML padrão
    
    // Remover mensagens de erro anteriores
    const existingError = form.querySelector('.error-message');
    if (existingError) existingError.remove();

    // 1. Obter os dados do formulário
    const fullName = document.getElementById('full_name').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    const organization = document.getElementById('organization').value;
    const termsAccepted = document.getElementById('terms').checked;

    // 2. Validações
    if (password !== confirmPassword) {
        displayError("As passwords não coincidem.");
        return;
    }
    if (!termsAccepted) {
        displayError("Tem de aceitar os Termos e Condições.");
        return;
    }

    try {
        // Desativar o botão durante o processamento
        registerButton.disabled = true;
        registerButton.textContent = "A registar...";
        
        // 3. Registo de Utilizador (Firebase Authentication - Guarda a password de forma segura/encriptada)
        const userCredential = await createUserWithEmailAndPassword(auth, email, password);
        const user = userCredential.user;
        
        // 4. Guardar dados adicionais do utilizador (Firestore)
        // COLEÇÃO: 'User' (Conforme a sua imagem)
        const timestamp = new Date();
        
        await setDoc(doc(db, "User", user.uid), { // <-- Coleção "User"
            FullName: fullName,                  // <-- Campo "FullName"
            Organization: organization === "" ? "Não especificada" : organization, // <-- Campo "Organization"
            Role: "/Roles/free",                 // <-- Campo "Role" padrão para novos utilizadores
            createdAt: timestamp,                // <-- Campo "createdAt"
            email: email,                        // <-- Campo "email"
            updatedAt: timestamp                 // <-- Campo "updatedAt" (inicialmente igual a createdAt)
        });
        
        // 5. Sucesso
        alert("Registo concluído com sucesso!");
        window.location.href = 'LandingPage.html'; 

    } catch (error) {
        // 6. Tratamento de Erros do Firebase
        const errorCode = error.code;
        let errorMessage = "Ocorreu um erro no registo.";

        if (errorCode === 'auth/email-already-in-use') {
            errorMessage = "O email fornecido já está em uso.";
        } else if (errorCode === 'auth/invalid-email') {
            errorMessage = "O formato do email é inválido.";
        } else if (errorCode === 'auth/weak-password') {
            errorMessage = "A password deve ter pelo menos 6 caracteres.";
        } else {
             console.error("Erro desconhecido:", error);
             errorMessage = `Erro: ${errorCode.replace('auth/', '')}`;
        }

        displayError(errorMessage);

    } finally {
        // Reativar o botão no final
        registerButton.disabled = false;
        registerButton.textContent = "Register";
    }
});

// Função auxiliar para exibir erros
function displayError(message) {
    const errorElement = document.createElement('p');
    errorElement.className = 'error-message';
    errorElement.style.color = 'red';
    errorElement.style.marginTop = '10px';
    errorElement.textContent = message;
    // Insere a mensagem de erro antes do botão
    form.insertBefore(errorElement, registerButton);
}


// ====================================================================
// PARTE 2: LÓGICA DOS MODAIS (O CÓDIGO QUE FORNECEU)
// ====================================================================

// Abrir modal de Termos & Privacidade
const modalLinks = document.querySelectorAll('.link-modal');

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