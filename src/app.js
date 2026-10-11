// Browser UI. Generation, entropy and breach-check logic live in generator.js (tested).
import {
  generatePassword, generatePassphrase, passwordEntropy, passphraseEntropy, poolSize,
  rateEntropy, crackTimeText, sha1Hex, splitHash, countInRange, RANGE_URL,
} from './generator.js';
import { WORDS } from './wordlist.js';

const $ = (id) => document.getElementById(id);

// ---------- Tabs (keyboard: left/right arrows) ----------
const tabs = [...document.querySelectorAll('[role="tab"]')];
function selectTab(tab) {
  for (const t of tabs) {
    const on = t === tab;
    t.setAttribute('aria-selected', String(on));
    t.tabIndex = on ? 0 : -1;
    $(t.getAttribute('aria-controls')).hidden = !on;
  }
}
tabs.forEach((tab, i) => {
  tab.addEventListener('click', () => selectTab(tab));
  tab.addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    const next = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
    selectTab(next);
    next.focus();
  });
});

// ---------- Strength meter ----------
function renderMeter(el, bits) {
  const rating = rateEntropy(bits);
  const filled = Math.min(4, Math.max(1, Math.floor(bits / 25)));
  el.dataset.level = rating.label.toLowerCase();
  el.innerHTML = `
    <div class="meter-bar" aria-hidden="true">${[1, 2, 3, 4].map((n) => `<span class="${n <= filled ? 'on' : ''}"></span>`).join('')}</div>
    <p><strong>${rating.label}</strong>, ${Math.round(bits)} bits. ${rating.note}</p>
    <p class="crack">Time to guess at 10 billion tries a second: ${crackTimeText(bits)}.</p>`;
}

// ---------- Password ----------
const pwOpts = () => ({
  length: Number($('pw-length').value),
  upper: $('pw-upper').checked,
  lower: $('pw-lower').checked,
  numbers: $('pw-numbers').checked,
  symbols: $('pw-symbols').checked,
  avoidLookalikes: $('pw-lookalikes').checked,
});
function newPassword() {
  const opts = pwOpts();
  try {
    $('pw-out').textContent = generatePassword(opts);
    $('pw-error').hidden = true;
    renderMeter($('pw-meter'), passwordEntropy(opts.length, poolSize(opts)));
  } catch (err) {
    $('pw-error').textContent = 'Tick at least one type of character.';
    $('pw-error').hidden = false;
  }
}
$('pw-length').addEventListener('input', () => { $('pw-length-value').textContent = $('pw-length').value; newPassword(); });
for (const id of ['pw-upper', 'pw-lower', 'pw-numbers', 'pw-symbols', 'pw-lookalikes']) $(id).addEventListener('change', newPassword);
$('pw-new').addEventListener('click', newPassword);

// ---------- Passphrase ----------
const ppOpts = () => ({
  words: Number($('pp-words').value),
  separator: $('pp-sep').value,
  capitalise: $('pp-cap').checked,
  addNumber: $('pp-num').checked,
});
function newPassphrase() {
  const opts = ppOpts();
  $('pp-out').textContent = generatePassphrase(opts, WORDS);
  renderMeter($('pp-meter'), passphraseEntropy(opts.words, WORDS.length, opts.addNumber));
}
$('pp-words').addEventListener('input', () => { $('pp-words-value').textContent = $('pp-words').value; newPassphrase(); });
for (const id of ['pp-sep', 'pp-cap', 'pp-num']) $(id).addEventListener('change', newPassphrase);
$('pp-new').addEventListener('click', newPassphrase);

// ---------- Copy ----------
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-copy]');
  if (!btn) return;
  const text = $(btn.dataset.copy).textContent;
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = 'Copied';
  } catch {
    btn.textContent = 'Copy failed';
  }
  setTimeout(() => { btn.textContent = 'Copy'; }, 1800);
});

// ---------- Breach check (k-anonymity) ----------
$('check-show').addEventListener('click', () => {
  const input = $('check-input');
  const showing = input.type === 'text';
  input.type = showing ? 'password' : 'text';
  $('check-show').textContent = showing ? 'Show' : 'Hide';
  $('check-show').setAttribute('aria-pressed', String(!showing));
});

$('check-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const out = $('check-result');
  const value = $('check-input').value;
  if (!value) { out.className = 'check-result'; out.textContent = 'Type a password to check.'; return; }
  out.className = 'check-result';
  out.textContent = 'Checking…';
  try {
    const { prefix, suffix } = splitHash(await sha1Hex(value));
    const res = await fetch(RANGE_URL + prefix, { headers: { 'Add-Padding': 'true' } });
    if (!res.ok) throw new Error(`Service replied ${res.status}`);
    const count = countInRange(await res.text(), suffix);
    if (count > 0) {
      out.className = 'check-result bad';
      out.innerHTML = `<strong>Seen ${count.toLocaleString('en-GB')} ${count === 1 ? 'time' : 'times'} in data breaches.</strong> Attackers try leaked passwords first, so stop using this one anywhere and change it on every account that uses it.`;
    } else {
      out.className = 'check-result good';
      out.innerHTML = '<strong>Not found in known breaches.</strong> That\'s good, but it doesn\'t prove it\'s strong. Make sure it\'s long and only used for one account.';
    }
  } catch {
    out.className = 'check-result';
    out.textContent = 'Couldn\'t reach the breach-check service. Check your internet connection and try again.';
  }
});

newPassword();
newPassphrase();
