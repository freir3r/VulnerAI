// CONFIGURAÇÃO DO FIREBASE

import { initializeApp } from "https://www.gstatic.com/firebasejs/9.22.2/firebase-app.js";
import { 
    getAuth, 
    signInWithEmailAndPassword, 
    sendPasswordResetEmail 
} from "https://www.gstatic.com/firebasejs/9.22.2/firebase-auth.js";

  const firebaseConfig = {
    apiKey: "AIzaSyBuaJdeJSHhn8zvOt3COp1fy987Zx4Da9k",
    authDomain: "vulnerai.firebaseapp.com",
    projectId: "vulnerai",
    storageBucket: "vulnerai.firebasestorage.app",
    messagingSenderId: "576892753213",
    appId: "1:576892753213:web:b418a23c16b808c1d4a154",
    measurementId: "G-K38GLCC5XL"
  };

// Inicializa o Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);



// VARIÁVEIS DO DOM E FUNÇÕES AUXILIARES
const form = document.getElementById('loginForm');
// Usamos as IDs dos inputs:
const emailInput = document.getElementById('email'); 
const pwdInput = document.getElementById('password'); 
const forgotEmailInput = document.getElementById('forgotEmail');
const sendForgotBtn = document.getElementById('sendForgot');
const forgotErrorDiv = document.getElementById('forgotError');

const AUTH_KEY = 'vulnerai.auth';

// Função auxiliar simples para validação de email
function validEmail(e) { return /\S+@\S+\.\S+/.test(e); }



// FUNÇÃO DE LOGIN: SÓ REDIRECIONA SE O FIREBASE APROVAR
form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const email = emailInput.value.trim();
    const password = pwdInput.value;

    // Validação básica do lado do cliente
    if (!validEmail(email)) { 
        alert('Por favor introduza um email válido.'); 
        return; 
    }
    // A validação de minlength="6" já está no HTML, mas verificamos aqui também
    if (password.length < 6) { 
        alert('A password tem de ter pelo menos 6 caracteres.'); 
        return; 
    }

    try {
        // Tenta fazer login com email e password usando o Firebase
        const userCredential = await signInWithEmailAndPassword(auth, email, password);
        const user = userCredential.user;

        // Login bem-sucedido!
        // Guarda o estado de login (opcional)
        localStorage.setItem(AUTH_KEY, JSON.stringify({ uid: user.uid, email: user.email, ts: Date.now() }));
        
        // **REDIRECIONA APENAS AQUI**
        window.location.href = 'dashboard.html';

    } catch (error) {
        // Lida com erros do Firebase
        const errorCode = error.code;
        console.error("Erro de Login:", errorCode, error.message);

        let errorMessage = "Ocorreu um erro no login. Tente novamente.";

        switch (errorCode) {
            case 'auth/user-not-found':
            case 'auth/wrong-password':
                errorMessage = "Email ou password incorretos.";
                break;
            case 'auth/invalid-email':
                errorMessage = "O email fornecido não é válido.";
                break;
            case 'auth/user-disabled':
                errorMessage = "Esta conta foi desativada.";
                break;
            default:
                errorMessage = "Não foi possível iniciar sessão. Verifique a sua ligação ou tente mais tarde.";
                break;
        }

        alert(errorMessage);
    }
});

// FUNÇÃO DE RECUPERAÇÃO DE PASSWORD COM FIREBASE
sendForgotBtn.addEventListener('click', async () => {
    const email = forgotEmailInput.value.trim();
    forgotErrorDiv.style.display = 'none';

    if (!validEmail(email)) { 
        forgotErrorDiv.style.display = 'block'; 
        return; 
    }

    try {
        // Envia o email de recuperação de password pelo Firebase
        await sendPasswordResetEmail(auth, email);

        // Mensagem de sucesso (mantida genérica por segurança, como recomendado pela Firebase)
        alert('Se o email existir no sistema, receberá instruções para repor a password.');
        
        // Chama a função global definida no script do HTML
        if (window.closeModal) window.closeModal(); 

    } catch (error) {
        // Lidar com erros específicos (e manter a mensagem genérica por segurança)
        console.error("Erro ao enviar email de recuperação:", error.code);
        alert('Se o email existir no sistema, receberá instruções para repor a password.');
        if (window.closeModal) window.closeModal(); 
    }
});