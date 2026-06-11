// --- ELEMENTY DOM ---
const loginView = document.getElementById('login-view');
const dashboardView = document.getElementById('dashboard-view');

// Elementy logowania/rejestracji
let isLoginMode = true;
const authForm = document.getElementById('auth-form');
const toggleBtn = document.getElementById('toggle-form-btn');
const formTitle = document.getElementById('form-title');
const submitBtn = document.getElementById('submit-btn');
const totpGroup = document.getElementById('totp-group');
const entropyContainer = document.getElementById('entropy-container');
const messageDiv = document.getElementById('message');

// Elementy entropii
const passwordInput = document.getElementById('password');
const meterFill = document.getElementById('meter-fill');
const entropyText = document.getElementById('entropy-text');

// --- ROUTER (Silnik SPA decydujący, co pokazać) ---
function render() {
    const token = localStorage.getItem('access_token');
    if (token) {
        // Zalogowany -> pokaż dashboard
        loginView.classList.add('hidden');
        dashboardView.classList.remove('hidden');
        document.getElementById('user-display-email').innerText = localStorage.getItem('user_email');
    } else {
        // Niezalogowany -> pokaż logowanie
        dashboardView.classList.add('hidden');
        loginView.classList.remove('hidden');
    }
}

// --- LOGIKA ENTROPII (Liczenie w locie) ---
passwordInput.addEventListener('input', function() {
    if (isLoginMode) return; // Liczymy tylko przy rejestracji

    const pass = this.value;
    if (!pass) {
        meterFill.style.width = '0%';
        entropyText.innerText = 'Entropia: 0 bitów';
        return;
    }

    let poolSize = 0;
    if (/[a-z]/.test(pass)) poolSize += 26;
    if (/[A-Z]/.test(pass)) poolSize += 26;
    if (/[0-9]/.test(pass)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(pass)) poolSize += 32;

    let entropy = 0;
    if (poolSize > 0) entropy = Math.round(pass.length * Math.log2(poolSize));

    entropyText.innerText = `Entropia: ${entropy} bitów`;

    if (entropy < 40) {
        meterFill.style.width = '30%';
        meterFill.style.backgroundColor = '#ff4d4d'; // Słabe
    } else if (entropy < 60) {
        meterFill.style.width = '60%';
        meterFill.style.backgroundColor = '#ffa64d'; // Średnie
    } else {
        meterFill.style.width = '100%';
        meterFill.style.backgroundColor = '#2eb82e'; // Silne
    }
});

// --- PRZEŁĄCZANIE TRYBU LOGOWANIE / REJESTRACJA ---
toggleBtn.addEventListener('click', () => {
    isLoginMode = !isLoginMode;
    messageDiv.classList.add('hidden');

    if (isLoginMode) {
        formTitle.innerText = 'Logowanie';
        submitBtn.innerText = 'Zaloguj się';
        toggleBtn.innerText = 'Nie masz konta? Zarejestruj się';
        totpGroup.classList.remove('hidden');
        entropyContainer.classList.add('hidden');
    } else {
        formTitle.innerText = 'Rejestracja';
        submitBtn.innerText = 'Utwórz konto';
        toggleBtn.innerText = 'Masz już konto? Zaloguj się';
        totpGroup.classList.add('hidden');
        entropyContainer.classList.remove('hidden');
        passwordInput.dispatchEvent(new Event('input')); // Odśwież pasek
    }
});

function showMessage(text, isSuccess) {
    messageDiv.innerText = text;
    messageDiv.className = isSuccess ? 'success' : 'error';
    messageDiv.classList.remove('hidden');
}

// --- WYSYŁANIE FORMULARZA DO FASTAPI ---
authForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const totp_code = document.getElementById('totp').value || null;

    const endpoint = isLoginMode ? '/auth/login' : '/auth/register';
    const payload = isLoginMode ? { email, password, totp_code } : { email, password };

    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();

        if (!res.ok) {
            let errorMsg = data.detail || "Wystąpił błąd";
            if (Array.isArray(data.detail)) errorMsg = data.detail[0].msg;
            showMessage(errorMsg, false);
        } else {
            if (isLoginMode) {
                // Zapisz token i przeładuj widok na Dashboard
                localStorage.setItem('access_token', data.access_token);
                localStorage.setItem('user_email', data.email);
                document.getElementById('password').value = ''; // Wyczyść hasło
                render();
            } else {
                showMessage("Konto utworzone! Przełącz na logowanie.", true);
            }
        }
    } catch (err) {
        showMessage("Błąd połączenia z serwerem.", false);
    }
});

// --- WYLOGOWANIE ---
document.getElementById('logout-btn').addEventListener('click', () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user_email');
    document.getElementById('qr-container').classList.add('hidden'); // Reset panelu 2FA
    render();
});

// --- KONFIGURACJA 2FA ---
document.getElementById('setup-2fa-btn').addEventListener('click', async () => {
    const email = localStorage.getItem('user_email');

    try {
        const res = await fetch('/auth/setup-2fa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email })
        });

        const data = await res.json();
        if (res.ok) {
            document.getElementById('qr-image').src = data.qr_code_url;
            document.getElementById('secret-text').innerText = data.secret;
            document.getElementById('qr-container').classList.remove('hidden');
            document.getElementById('setup-2fa-btn').innerText = "Zresetuj 2FA";
        }
    } catch (err) {
        alert("Błąd podczas konfiguracji 2FA.");
    }
});

// --- INICJALIZACJA APLIKACJI ---
render();