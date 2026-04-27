const API_URL = 'http://localhost:5000';

const canvas = document.getElementById('matrixCanvas');
const ctx = canvas.getContext('2d');

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
});

const cols = Math.floor(canvas.width / 20);
const drops = Array(cols).fill(1);

function drawMatrix() {
    ctx.fillStyle = 'rgba(5, 13, 26, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#0ea5e9';
    ctx.font = '14px Share Tech Mono';

    drops.forEach((y, i) => {
        const char = Math.random() > 0.5 ? '1' : '0';
        ctx.fillText(char, i * 20, y * 20);
        if (y * 20 > canvas.height && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
    });
}

setInterval(drawMatrix, 60);

document.getElementById('urlInput').addEventListener('input', function () {
    document.getElementById('clearBtn').style.display = this.value ? 'block' : 'none';
});

document.getElementById('urlInput').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') analyzeURL();
});

function clearInput() {
    document.getElementById('urlInput').value = '';
    document.getElementById('clearBtn').style.display = 'none';
    document.getElementById('urlInput').focus();
}

function tryExample(url) {
    document.getElementById('urlInput').value = url;
    document.getElementById('clearBtn').style.display = 'block';
    document.getElementById('urlInput').focus();
}

async function analyzeURL() {
    const url = document.getElementById('urlInput').value.trim();

    if (!url) { showToast('Please enter a URL first.'); return; }
    if (url.length < 4) { showToast('URL is too short.'); return; }

    setLoading(true);
    document.getElementById('resultsSection').style.display = 'none';

    try {
        const res = await fetch(`${API_URL}/predict`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        if (!res.ok) throw new Error(`Server error: ${res.status}`);

        const data = await res.json();
        if (data.error) throw new Error(data.error);

        showResults(data);

    } catch (err) {
        if (err.message.includes('fetch') || err.message.includes('Network')) {
            showToast('Cannot reach server. Make sure backend is running: python backend/app.py');
        } else {
            showToast(`Error: ${err.message}`);
        }
    }

    setLoading(false);
}

function showResults(data) {
    const { prediction, label, confidence, url,
            warnings, attack_type, attack_description, advice } = data;

    const card = document.getElementById('verdictCard');
    card.className = 'verdict-card';
    card.classList.add(label.toLowerCase());

    document.getElementById('verdictEmoji').textContent =
        prediction === 0 ? '✅' : prediction === 1 ? '⚠️' : '🚨';

    document.getElementById('verdictLabel').textContent =
        prediction === 0 ? 'Safe URL' : prediction === 1 ? 'Suspicious URL' : 'Malicious URL';

    document.getElementById('verdictURL').textContent =
        url.length > 65 ? url.slice(0, 65) + '...' : url;

    document.getElementById('confidencePill').textContent =
        `Confidence: ${confidence}%`;

    const warningsCard = document.getElementById('warningsCard');
    const warningsList = document.getElementById('warningsList');
    warningsList.innerHTML = '';

    if (warnings && warnings.length > 0) {
        warnings.forEach(w => {
            const li = document.createElement('li');
            li.textContent = w;
            warningsList.appendChild(li);
        });
        warningsCard.style.display = 'block';
    } else {
        warningsCard.style.display = 'none';
    }

    const attackCard = document.getElementById('attackCard');
    if (prediction > 0 && attack_type) {
        document.getElementById('attackPill').textContent = attack_type;
        document.getElementById('attackDesc').textContent = attack_description;
        attackCard.style.display = 'block';
    } else {
        attackCard.style.display = 'none';
    }

    const adviceList = document.getElementById('adviceList');
    adviceList.innerHTML = '';
    advice.forEach(a => {
        const li = document.createElement('li');
        li.textContent = a;
        adviceList.appendChild(li);
    });

    const section = document.getElementById('resultsSection');
    section.style.display = 'block';
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function setLoading(on) {
    const btn = document.getElementById('scanBtn');
    document.getElementById('btnText').style.display   = on ? 'none'         : 'inline';
    document.getElementById('btnLoading').style.display = on ? 'inline'       : 'none';
    btn.disabled = on;
}

function showToast(msg) {
    document.querySelector('.err-toast')?.remove();
    const t = document.createElement('div');
    t.className = 'err-toast';
    t.textContent = msg;
    t.style.cssText = `
        position:fixed; top:20px; right:20px;
        background:#ef4444; color:#fff;
        padding:13px 20px; border-radius:10px;
        font-size:0.9rem; font-weight:600;
        z-index:9999; max-width:380px;
        box-shadow:0 8px 24px rgba(239,68,68,0.35);
        font-family:'Rajdhani',sans-serif;
        animation: fadeUp 0.3s ease;
    `;
    document.body.appendChild(t);
    setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity 0.3s'; setTimeout(() => t.remove(), 300); }, 4000);
    setLoading(false);
}

function resetScan() {
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('urlInput').value = '';
    document.getElementById('clearBtn').style.display = 'none';
    window.scrollTo({ top: 0, behavior: 'smooth' });
    document.getElementById('urlInput').focus();
}