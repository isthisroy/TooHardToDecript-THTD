/**
 * THTD // TOO HARD TO DECRYPT
 * Client-Side Cryptographic Vault Engine
 * 
 * Pipeline:
 * 1. 128-bit True Entropy -> SHA-256 (4-bit Checksum) -> 12 BIP-39 Words
 * 2. 12 Words + 16-byte CSPRNG Salt -> Argon2id (64MB, 3 iterations) -> 256-bit Key
 * 3. Metadata (JSON) + File Bytes -> AES-256-GCM Authenticated Ciphertext
 * 4. Export: [Magic "THTD"] [Version 1B] [Salt 16B] [IV 12B] [Ciphertext + Tag]
 * 5. HTML5 Canvas Keycard Generation (.png)
 */

(function () {
  'use strict';

  // Constants
  const MAGIC_BYTES = new Uint8Array([0x54, 0x48, 0x54, 0x44]); // "THTD"
  const FORMAT_VERSION = 1;
  const SALT_LENGTH = 16;
  const IV_LENGTH = 12;

  // State
  let encryptState = {
    file: null,
    mnemonic: [],
    salt: null,
    encryptedBlob: null,
    outputFilename: '',
    keycardBlob: null
  };

  let decryptState = {
    file: null,
    decryptedBlob: null,
    originalName: ''
  };

  // DOM Elements
  const tabEncrypt = document.getElementById('tab-encrypt');
  const tabDecrypt = document.getElementById('tab-decrypt');
  const tabAbout = document.getElementById('tab-about');
  const viewEncrypt = document.getElementById('view-encrypt');
  const viewDecrypt = document.getElementById('view-decrypt');
  const viewAbout = document.getElementById('view-about');

  // Encrypt Elements
  const encDropZone = document.getElementById('enc-drop-zone');
  const encFileInput = document.getElementById('enc-file-input');
  const encFileMeta = document.getElementById('enc-file-meta');
  const encSelectedName = document.getElementById('enc-selected-name');
  const encSelectedSize = document.getElementById('enc-selected-size');
  const encSelectedType = document.getElementById('enc-selected-type');
  const encClearFile = document.getElementById('enc-clear-file');
  const encCustomFilename = document.getElementById('enc-custom-filename');
  const encSecretMessage = document.getElementById('enc-secret-message');
  const btnStartEncrypt = document.getElementById('btn-start-encrypt');
  const encProcessing = document.getElementById('enc-processing');
  const encResult = document.getElementById('enc-result');
  const encWordsGrid = document.getElementById('enc-words-grid');
  const btnToggleMask = document.getElementById('btn-toggle-mask');
  const maskIcon = document.getElementById('mask-icon');
  const maskText = document.getElementById('mask-text');
  const btnCopyPhrase = document.getElementById('btn-copy-phrase');
  const keycardCanvas = document.getElementById('keycard-canvas');
  const btnDownloadEnc = document.getElementById('btn-download-enc');
  const lblDownloadEnc = document.getElementById('lbl-download-enc');
  const btnDownloadPng = document.getElementById('btn-download-png');
  const btnEncryptAnother = document.getElementById('btn-encrypt-another');

  // Decrypt Elements
  const decDropZone = document.getElementById('dec-drop-zone');
  const decFileInput = document.getElementById('dec-file-input');
  const decFileMeta = document.getElementById('dec-file-meta');
  const decSelectedName = document.getElementById('dec-selected-name');
  const decSelectedSize = document.getElementById('dec-selected-size');
  const decClearFile = document.getElementById('dec-clear-file');
  const mnemonicStatusBadge = document.getElementById('mnemonic-status-badge');
  const mnemonicQuickPaste = document.getElementById('mnemonic-quick-paste');
  const btnPasteClipboard = document.getElementById('btn-paste-clipboard');
  const decWordsGrid = document.getElementById('dec-words-grid');
  const btnStartDecrypt = document.getElementById('btn-start-decrypt');
  const decProcessing = document.getElementById('dec-processing');
  const decResult = document.getElementById('dec-result');
  const resFilename = document.getElementById('res-filename');
  const resFilesize = document.getElementById('res-filesize');
  const resFiletype = document.getElementById('res-filetype');
  const resTimestamp = document.getElementById('res-timestamp');
  const resNoteContainer = document.getElementById('res-note-container');
  const resNoteText = document.getElementById('res-note-text');
  const btnDownloadDecrypted = document.getElementById('btn-download-decrypted');
  const lblDownloadDecrypted = document.getElementById('lbl-download-decrypted');
  const btnDecryptAnother = document.getElementById('btn-decrypt-another');

  // Toast Container
  const toastContainer = document.getElementById('toast-container');

  // ==========================================
  // Helper: Toast Notifications
  // ==========================================
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type === 'success' ? 'toast-success' : type === 'error' ? 'toast-error' : ''}`;
    
    let icon = 'ℹ️';
    if (type === 'success') icon = '✓';
    if (type === 'error') icon = '⚠';

    toast.innerHTML = `<span>${icon}</span><span>${escapeHtml(message)}</span>`;
    toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(8px)';
      toast.style.transition = 'all 0.25s ease';
      setTimeout(() => toast.remove(), 260);
    }, 3500);
  }

  function escapeHtml(str) {
    return str.replace(/[&<>'"]/g, tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag));
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  // ==========================================
  // Navigation Tabs
  // ==========================================
  function switchTab(tabId) {
    [tabEncrypt, tabDecrypt, tabAbout].forEach(t => t.classList.remove('active'));
    [viewEncrypt, viewDecrypt, viewAbout].forEach(v => v.classList.remove('active'));

    if (tabId === 'encrypt') {
      tabEncrypt.classList.add('active');
      viewEncrypt.classList.add('active');
    } else if (tabId === 'decrypt') {
      tabDecrypt.classList.add('active');
      viewDecrypt.classList.add('active');
    } else if (tabId === 'about') {
      tabAbout.classList.add('active');
      viewAbout.classList.add('active');
    }
  }

  tabEncrypt.addEventListener('click', () => switchTab('encrypt'));
  tabDecrypt.addEventListener('click', () => switchTab('decrypt'));
  tabAbout.addEventListener('click', () => switchTab('about'));

  // ==========================================
  // BIP-39 Cryptographic Utilities
  // ==========================================
  async function generate12Words() {
    if (typeof BIP39_WORDLIST === 'undefined' || BIP39_WORDLIST.length !== 2048) {
      throw new Error('BIP-39 dictionary not loaded or incomplete');
    }

    // 128-bit cryptographically secure entropy
    const entropy = new Uint8Array(16);
    crypto.getRandomValues(entropy);

    // Compute SHA-256 hash for checksum
    const hashBuffer = await crypto.subtle.digest('SHA-256', entropy);
    const hashArray = new Uint8Array(hashBuffer);

    // Convert entropy bytes to bit string
    let bitString = '';
    for (let i = 0; i < entropy.length; i++) {
      bitString += entropy[i].toString(2).padStart(8, '0');
    }

    // First 4 bits of hash as checksum (128 / 32 = 4 bits)
    const checksumBits = hashArray[0].toString(2).padStart(8, '0').slice(0, 4);
    bitString += checksumBits; // Total: 132 bits

    // Split into 12 chunks of 11 bits
    const words = [];
    for (let i = 0; i < 12; i++) {
      const slice = bitString.slice(i * 11, (i + 1) * 11);
      const index = parseInt(slice, 2);
      words.push(BIP39_WORDLIST[index]);
    }

    return words;
  }

  async function validateMnemonic(words) {
    if (!Array.isArray(words) || words.length !== 12) return false;
    if (typeof BIP39_WORDLIST === 'undefined') return false;

    let bitString = '';
    for (const w of words) {
      const cleanWord = w.trim().toLowerCase();
      const index = BIP39_WORDLIST.indexOf(cleanWord);
      if (index === -1) return false;
      bitString += index.toString(2).padStart(11, '0');
    }

    const entropyBits = bitString.slice(0, 128);
    const checksumBits = bitString.slice(128);

    const entropy = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      entropy[i] = parseInt(entropyBits.slice(i * 8, (i + 1) * 8), 2);
    }

    const hashBuffer = await crypto.subtle.digest('SHA-256', entropy);
    const hashArray = new Uint8Array(hashBuffer);
    const calculatedChecksum = hashArray[0].toString(2).padStart(8, '0').slice(0, 4);

    return calculatedChecksum === checksumBits;
  }

  // ==========================================
  // Argon2id Key Derivation
  // ==========================================
  function getArgon2Engine() {
    if (typeof hashwasm !== 'undefined' && typeof hashwasm.argon2id === 'function') {
      return hashwasm;
    }
    if (window.hashwasm && typeof window.hashwasm.argon2id === 'function') {
      return window.hashwasm;
    }
    if (window.hashWasm && typeof window.hashWasm.argon2id === 'function') {
      return window.hashWasm;
    }
    return null;
  }

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = src;
      s.onload = resolve;
      s.onerror = reject;
      document.head.appendChild(s);
    });
  }

  async function deriveArgon2Key(wordsArray, salt) {
    let engine = getArgon2Engine();

    // Fallback: If local file wasn't loaded (e.g. file moved or network sandbox), try CDN
    if (!engine) {
      try {
        await loadScript('https://cdn.jsdelivr.net/npm/hash-wasm@4/dist/argon2.umd.min.js');
        engine = getArgon2Engine();
      } catch (cdnErr) {
        console.warn('CDN fallback load failed:', cdnErr);
      }
    }

    if (!engine || typeof engine.argon2id !== 'function') {
      throw new Error('Argon2id WebAssembly engine not loaded. Please verify lib/argon2.umd.min.js is present.');
    }

    const passphrase = wordsArray.map(w => w.trim().toLowerCase()).join(' ');

    // Memory-hard Argon2id KDF: 64 MB (65536 KB), 3 iterations, 32 bytes (256-bit key)
    const keyBytes = await engine.argon2id({
      password: passphrase,
      salt: salt,
      iterations: 3,
      memorySize: 65536,
      hashLength: 32,
      parallelism: 1,
      outputType: 'binary'
    });

    return keyBytes;
  }

  // ==========================================
  // Encrypt Flow
  // ==========================================
  function setupEncryptDropZone() {
    ['dragenter', 'dragover'].forEach(eventName => {
      encDropZone.addEventListener(eventName, e => {
        e.preventDefault();
        e.stopPropagation();
        encDropZone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      encDropZone.addEventListener(eventName, e => {
        e.preventDefault();
        e.stopPropagation();
        encDropZone.classList.remove('dragover');
      });
    });

    encDropZone.addEventListener('drop', e => {
      const files = e.dataTransfer.files;
      if (files && files.length > 0) handleFileSelected(files[0]);
    });

    encFileInput.addEventListener('change', e => {
      if (e.target.files && e.target.files.length > 0) {
        handleFileSelected(e.target.files[0]);
      }
    });

    encClearFile.addEventListener('click', e => {
      e.stopPropagation();
      clearSelectedFile();
    });
  }

  function handleFileSelected(file) {
    encryptState.file = file;
    encSelectedName.textContent = file.name;
    encSelectedSize.textContent = formatBytes(file.size);
    encSelectedType.textContent = file.type || 'Unknown format / binary';

    encDropZone.querySelector('.drop-content').classList.add('hidden');
    encFileMeta.classList.remove('hidden');

    // Auto-fill suggested output filename
    const baseName = file.name;
    encCustomFilename.value = baseName;

    btnStartEncrypt.disabled = false;
  }

  function clearSelectedFile() {
    encryptState.file = null;
    encFileInput.value = '';
    encDropZone.querySelector('.drop-content').classList.remove('hidden');
    encFileMeta.classList.add('hidden');
    encCustomFilename.value = '';
    btnStartEncrypt.disabled = true;
  }

  btnStartEncrypt.addEventListener('click', async () => {
    if (!encryptState.file) return;

    try {
      // Switch UI to processing
      document.getElementById('encrypt-form').classList.add('hidden');
      encProcessing.classList.remove('hidden');

      // Step 1: Generate 12 BIP-39 words
      const mnemonic = await generate12Words();
      encryptState.mnemonic = mnemonic;

      // Step 2: Random 16-byte salt for Argon2id
      const salt = new Uint8Array(SALT_LENGTH);
      crypto.getRandomValues(salt);
      encryptState.salt = salt;

      // Step 3: Derive 256-bit AES key via Argon2id
      const rawKey = await deriveArgon2Key(mnemonic, salt);
      const aesKey = await crypto.subtle.importKey(
        'raw',
        rawKey,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
      );

      // Step 4: Random 12-byte IV for AES-GCM
      const iv = new Uint8Array(IV_LENGTH);
      crypto.getRandomValues(iv);

      // Step 5: Read original file buffer
      const fileBuffer = await encryptState.file.arrayBuffer();

      // Step 6: Package Metadata (JSON)
      const metadata = {
        fileName: encryptState.file.name,
        fileType: encryptState.file.type || 'application/octet-stream',
        fileSize: encryptState.file.size,
        timestamp: Date.now(),
        message: encSecretMessage.value.trim()
      };

      const metaString = JSON.stringify(metadata);
      const metaBytes = new TextEncoder().encode(metaString);

      // Construct plaintext payload: [4 bytes BigEndian meta length] + [metaBytes] + [fileBytes]
      const metaLen = metaBytes.length;
      const payloadBuffer = new Uint8Array(4 + metaLen + fileBuffer.byteLength);
      const view = new DataView(payloadBuffer.buffer);
      view.setUint32(0, metaLen, false); // big-endian
      payloadBuffer.set(metaBytes, 4);
      payloadBuffer.set(new Uint8Array(fileBuffer), 4 + metaLen);

      // Step 7: Encrypt with AES-256-GCM
      const ciphertextBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        aesKey,
        payloadBuffer
      );

      // Step 8: Assemble final binary container
      // Header: [4B Magic: 'THTD'] + [1B Version: 1] + [16B Salt] + [12B IV] + [Ciphertext + Auth Tag]
      const totalHeaderLength = 4 + 1 + SALT_LENGTH + IV_LENGTH;
      const finalContainer = new Uint8Array(totalHeaderLength + ciphertextBuffer.byteLength);

      finalContainer.set(MAGIC_BYTES, 0);
      finalContainer[4] = FORMAT_VERSION;
      finalContainer.set(salt, 5);
      finalContainer.set(iv, 5 + SALT_LENGTH);
      finalContainer.set(new Uint8Array(ciphertextBuffer), totalHeaderLength);

      encryptState.encryptedBlob = new Blob([finalContainer], { type: 'application/octet-stream' });

      // Determine output filename
      let outName = encCustomFilename.value.trim();
      if (!outName) outName = encryptState.file.name;
      if (!outName.toLowerCase().endsWith('.enc')) outName += '.enc';
      encryptState.outputFilename = outName;

      // Step 9: Render 12 Words to UI
      renderWordsGrid(mnemonic);

      // Step 10: Generate Keycard Image (.png)
      await renderKeycardCanvas(mnemonic, metadata);

      // Update UI labels
      lblDownloadEnc.textContent = `Download ${outName}`;

      // Show result view
      encProcessing.classList.add('hidden');
      encResult.classList.remove('hidden');

      showToast('Vault created and encrypted successfully!', 'success');

    } catch (err) {
      console.error(err);
      encProcessing.classList.add('hidden');
      document.getElementById('encrypt-form').classList.remove('hidden');
      showToast(`Encryption failed: ${err.message}`, 'error');
    }
  });

  function renderWordsGrid(words) {
    encWordsGrid.innerHTML = '';
    words.forEach((word, index) => {
      const chip = document.createElement('div');
      chip.className = 'word-chip';
      chip.innerHTML = `
        <span class="word-index">${String(index + 1).padStart(2, '0')}.</span>
        <span class="word-val">${escapeHtml(word)}</span>
      `;
      encWordsGrid.appendChild(chip);
    });
  }

  // Toggle Mask / Reveal Words
  let wordsMasked = false;
  btnToggleMask.addEventListener('click', () => {
    wordsMasked = !wordsMasked;
    const wordVals = encWordsGrid.querySelectorAll('.word-val');
    wordVals.forEach(v => v.classList.toggle('masked', wordsMasked));
    maskText.textContent = wordsMasked ? 'Reveal Words' : 'Hide Words';
    maskIcon.textContent = wordsMasked ? '🔒' : '👁️';
  });

  // Copy All Words
  btnCopyPhrase.addEventListener('click', async () => {
    if (!encryptState.mnemonic || encryptState.mnemonic.length === 0) return;
    const phrase = encryptState.mnemonic.join(' ');
    try {
      await navigator.clipboard.writeText(phrase);
      showToast('12 words copied to clipboard!', 'success');
    } catch {
      showToast('Failed to copy. Please manually select the words.', 'error');
    }
  });

  // Download .enc file
  btnDownloadEnc.addEventListener('click', () => {
    if (!encryptState.encryptedBlob) return;
    triggerDownload(encryptState.encryptedBlob, encryptState.outputFilename);
  });

  // Download .png Keycard
  btnDownloadPng.addEventListener('click', () => {
    if (!encryptState.keycardBlob) return;
    const keycardName = `${encryptState.file.name.replace(/\.[^/.]+$/, '')}_THTD_keycard.png`;
    triggerDownload(encryptState.keycardBlob, keycardName);
  });

  // Encrypt Another
  btnEncryptAnother.addEventListener('click', () => {
    clearSelectedFile();
    encSecretMessage.value = '';
    encResult.classList.add('hidden');
    document.getElementById('encrypt-form').classList.remove('hidden');
  });

  // ==========================================
  // Keycard Generator (HTML5 Canvas)
  // ==========================================
  async function renderKeycardCanvas(words, metadata) {
    const canvas = keycardCanvas;
    const ctx = canvas.getContext('2d');
    const width = 1200;
    const height = 700;
    canvas.width = width;
    canvas.height = height;

    // Background: Deep Obsidian
    const bgGrad = ctx.createLinearGradient(0, 0, width, height);
    bgGrad.addColorStop(0, '#07080a');
    bgGrad.addColorStop(0.5, '#0e1117');
    bgGrad.addColorStop(1, '#090a0d');
    ctx.fillStyle = bgGrad;
    ctx.fillRect(0, 0, width, height);

    // Subtle Cyber Grid
    ctx.strokeStyle = 'rgba(212, 255, 0, 0.04)';
    ctx.lineWidth = 1;
    const gridSize = 30;
    for (let x = 0; x < width; x += gridSize) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }
    for (let y = 0; y < height; y += gridSize) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    // Outer Card Border with Lime Corner Accents
    ctx.strokeStyle = '#1e2430';
    ctx.lineWidth = 2;
    ctx.strokeRect(30, 30, width - 60, height - 60);

    // Neon Accent Corners
    const cornerSize = 25;
    ctx.strokeStyle = '#d4ff00';
    ctx.lineWidth = 4;
    // Top-Left
    ctx.beginPath();
    ctx.moveTo(30, 30 + cornerSize); ctx.lineTo(30, 30); ctx.lineTo(30 + cornerSize, 30); ctx.stroke();
    // Top-Right
    ctx.beginPath();
    ctx.moveTo(width - 30 - cornerSize, 30); ctx.lineTo(width - 30, 30); ctx.lineTo(width - 30, 30 + cornerSize); ctx.stroke();
    // Bottom-Left
    ctx.beginPath();
    ctx.moveTo(30, height - 30 - cornerSize); ctx.lineTo(30, height - 30); ctx.lineTo(30 + cornerSize, height - 30); ctx.stroke();
    // Bottom-Right
    ctx.beginPath();
    ctx.moveTo(width - 30 - cornerSize, height - 30); ctx.lineTo(width - 30, height - 30); ctx.lineTo(width - 30, height - 30 - cornerSize); ctx.stroke();

    // Brand Header
    ctx.fillStyle = '#d4ff00';
    ctx.font = '800 32px "JetBrains Mono", monospace';
    ctx.fillText('THTD // TOO HARD TO DECRYPT', 60, 85);

    ctx.fillStyle = '#838c9e';
    ctx.font = '700 13px "JetBrains Mono", monospace';
    ctx.fillText('AUTHENTICATED RECOVERY KEYCARD — ZERO-KNOWLEDGE SPECIFICATION', 60, 110);

    // Target File Info Bar
    ctx.fillStyle = 'rgba(21, 25, 36, 0.9)';
    ctx.fillRect(60, 135, width - 120, 50);
    ctx.strokeStyle = '#222938';
    ctx.lineWidth = 1;
    ctx.strokeRect(60, 135, width - 120, 50);

    ctx.fillStyle = '#838c9e';
    ctx.font = '600 13px "Plus Jakarta Sans", sans-serif';
    ctx.fillText('TARGET FILE:', 80, 165);

    ctx.fillStyle = '#ffffff';
    ctx.font = '700 14px "JetBrains Mono", monospace';
    const shortName = metadata.fileName.length > 28 ? metadata.fileName.slice(0, 25) + '...' : metadata.fileName;
    ctx.fillText(shortName, 175, 165);

    ctx.fillStyle = '#838c9e';
    ctx.font = '600 13px "Plus Jakarta Sans", sans-serif';
    ctx.fillText('SIZE:', 480, 165);

    ctx.fillStyle = '#d4ff00';
    ctx.font = '700 14px "JetBrains Mono", monospace';
    ctx.fillText(formatBytes(metadata.fileSize), 525, 165);

    ctx.fillStyle = '#838c9e';
    ctx.font = '600 13px "Plus Jakarta Sans", sans-serif';
    ctx.fillText('CIPHER:', 680, 165);

    ctx.fillStyle = '#ffffff';
    ctx.font = '700 14px "JetBrains Mono", monospace';
    ctx.fillText('AES-256-GCM + Argon2id', 745, 165);

    ctx.fillStyle = '#838c9e';
    ctx.font = '600 13px "Plus Jakarta Sans", sans-serif';
    ctx.fillText('DATE:', 960, 165);

    ctx.fillStyle = '#ffffff';
    ctx.font = '700 13px "JetBrains Mono", monospace';
    const dateStr = new Date(metadata.timestamp).toISOString().split('T')[0];
    ctx.fillText(dateStr, 1010, 165);

    // 12 Words Grid (3 rows x 4 columns)
    const startX = 60;
    const startY = 215;
    const colWidth = (width - 120 - 45) / 4;
    const rowHeight = 70;
    const gapX = 15;
    const gapY = 15;

    for (let i = 0; i < 12; i++) {
      const col = i % 4;
      const row = Math.floor(i / 4);
      const x = startX + col * (colWidth + gapX);
      const y = startY + row * (rowHeight + gapY);

      // Chip Background
      ctx.fillStyle = '#0f1218';
      ctx.fillRect(x, y, colWidth, rowHeight);
      ctx.strokeStyle = '#222836';
      ctx.lineWidth = 1;
      ctx.strokeRect(x, y, colWidth, rowHeight);

      // Index Number
      ctx.fillStyle = '#d4ff00';
      ctx.font = '800 14px "JetBrains Mono", monospace';
      ctx.fillText(String(i + 1).padStart(2, '0') + '.', x + 16, y + 42);

      // Word
      ctx.fillStyle = '#ffffff';
      ctx.font = '700 18px "JetBrains Mono", monospace';
      ctx.fillText(words[i], x + 50, y + 43);
    }

    // Security Metrics & Brute-Force Estimate Banner
    const statsY = 490;
    ctx.fillStyle = 'rgba(212, 255, 0, 0.05)';
    ctx.fillRect(60, statsY, width - 120, 95);
    ctx.strokeStyle = 'rgba(212, 255, 0, 0.3)';
    ctx.lineWidth = 1;
    ctx.strokeRect(60, statsY, width - 120, 95);

    // Stat 1: Brute Force Time
    ctx.fillStyle = '#838c9e';
    ctx.font = '700 12px "JetBrains Mono", monospace';
    ctx.fillText('ESTIMATED BRUTE-FORCE TIME WITHOUT 12 WORDS', 80, statsY + 30);
    ctx.fillStyle = '#d4ff00';
    ctx.font = '800 24px "JetBrains Mono", monospace';
    ctx.fillText('> 10¹⁹ YEARS  (COMPUTATIONALLY IMPOSSIBLE)', 80, statsY + 68);

    // Stat 2: Keyspace
    ctx.fillStyle = '#838c9e';
    ctx.font = '700 12px "JetBrains Mono", monospace';
    ctx.fillText('TOTAL KEYSPACE ENTROPY', 780, statsY + 30);
    ctx.fillStyle = '#ffffff';
    ctx.font = '800 20px "JetBrains Mono", monospace';
    ctx.fillText('2¹²⁸ ≈ 3.4 × 10³⁸ COMBINATIONS', 780, statsY + 68);

    // Warning Footer
    ctx.fillStyle = '#ff7675';
    ctx.font = '700 12px "JetBrains Mono", monospace';
    ctx.fillText('⚠ CRITICAL DIRECTIVE: Store this recovery card offline. Anyone with these 12 words can decrypt this file.', 60, 625);
    ctx.fillStyle = '#636e72';
    ctx.font = '500 12px "JetBrains Mono", monospace';
    ctx.fillText('If these words are lost, mathematically zero recovery options exist. Zero-Knowledge Cryptography.', 60, 645);

    // Export Canvas to Blob
    return new Promise(resolve => {
      canvas.toBlob(blob => {
        encryptState.keycardBlob = blob;
        resolve(blob);
      }, 'image/png');
    });
  }

  // ==========================================
  // Decrypt Flow
  // ==========================================
  function setupDecryptInputs() {
    // Generate 12 input slots
    decWordsGrid.innerHTML = '';
    for (let i = 0; i < 12; i++) {
      const slot = document.createElement('div');
      slot.className = 'word-input-slot';
      slot.innerHTML = `
        <span class="slot-index">${String(i + 1).padStart(2, '0')}.</span>
        <input type="text" class="slot-input" data-index="${i}" placeholder="word ${i + 1}" autocomplete="off" spellcheck="false">
      `;
      decWordsGrid.appendChild(slot);
    }

    const slotInputs = decWordsGrid.querySelectorAll('.slot-input');

    slotInputs.forEach(input => {
      input.addEventListener('input', () => {
        handleWordsChanged();
      });

      // Handle keyboard navigation between slots
      input.addEventListener('keydown', e => {
        const idx = parseInt(input.getAttribute('data-index'), 10);
        if (e.key === ' ' || e.key === 'Enter') {
          e.preventDefault();
          if (idx < 11) slotInputs[idx + 1].focus();
        } else if (e.key === 'Backspace' && input.value === '' && idx > 0) {
          slotInputs[idx - 1].focus();
        }
      });
    });

    // Quick Paste Handler
    mnemonicQuickPaste.addEventListener('input', () => {
      distributePastedPhrase(mnemonicQuickPaste.value);
    });

    btnPasteClipboard.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        mnemonicQuickPaste.value = text;
        distributePastedPhrase(text);
      } catch {
        showToast('Clipboard access denied. Please paste manually into the input box.', 'error');
      }
    });

    // Drop Zone Setup
    ['dragenter', 'dragover'].forEach(eventName => {
      decDropZone.addEventListener(eventName, e => {
        e.preventDefault();
        e.stopPropagation();
        decDropZone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      decDropZone.addEventListener(eventName, e => {
        e.preventDefault();
        e.stopPropagation();
        decDropZone.classList.remove('dragover');
      });
    });

    decDropZone.addEventListener('drop', e => {
      const files = e.dataTransfer.files;
      if (files && files.length > 0) handleDecryptFileSelected(files[0]);
    });

    decFileInput.addEventListener('change', e => {
      if (e.target.files && e.target.files.length > 0) {
        handleDecryptFileSelected(e.target.files[0]);
      }
    });

    decClearFile.addEventListener('click', e => {
      e.stopPropagation();
      clearDecryptFile();
    });
  }

  function distributePastedPhrase(rawText) {
    const words = rawText.trim().split(/[\s,]+/).filter(Boolean);
    const slotInputs = decWordsGrid.querySelectorAll('.slot-input');

    if (words.length >= 12) {
      for (let i = 0; i < 12; i++) {
        slotInputs[i].value = words[i].toLowerCase();
      }
      mnemonicQuickPaste.value = '';
      showToast('12 words filled into slots!', 'success');
      handleWordsChanged();
    } else if (words.length > 0) {
      for (let i = 0; i < Math.min(words.length, 12); i++) {
        slotInputs[i].value = words[i].toLowerCase();
      }
      handleWordsChanged();
    }
  }

  async function handleWordsChanged() {
    const slotInputs = decWordsGrid.querySelectorAll('.slot-input');
    const words = Array.from(slotInputs).map(inp => inp.value.trim().toLowerCase());
    const filledCount = words.filter(Boolean).length;

    if (filledCount < 12) {
      mnemonicStatusBadge.className = 'badge-neutral';
      mnemonicStatusBadge.textContent = `${filledCount} of 12 words`;
      checkDecryptButtonReady(false);
      return;
    }

    // Check validity
    const isValid = await validateMnemonic(words);
    if (isValid) {
      mnemonicStatusBadge.className = 'badge-valid';
      mnemonicStatusBadge.textContent = '✓ Valid BIP-39 Seed';
      checkDecryptButtonReady(true);
    } else {
      mnemonicStatusBadge.className = 'badge-invalid';
      mnemonicStatusBadge.textContent = '⚠ Invalid Checksum / Typo';
      checkDecryptButtonReady(false);
    }
  }

  function handleDecryptFileSelected(file) {
    decryptState.file = file;
    decSelectedName.textContent = file.name;
    decSelectedSize.textContent = formatBytes(file.size);

    decDropZone.querySelector('.drop-content').classList.add('hidden');
    decFileMeta.classList.remove('hidden');

    handleWordsChanged();
  }

  function clearDecryptFile() {
    decryptState.file = null;
    decFileInput.value = '';
    decDropZone.querySelector('.drop-content').classList.remove('hidden');
    decFileMeta.classList.add('hidden');
    checkDecryptButtonReady(false);
  }

  function checkDecryptButtonReady(wordsValid) {
    const ready = Boolean(decryptState.file && wordsValid);
    btnStartDecrypt.disabled = !ready;
  }

  btnStartDecrypt.addEventListener('click', async () => {
    if (!decryptState.file) return;

    try {
      document.getElementById('decrypt-form').classList.add('hidden');
      decProcessing.classList.remove('hidden');

      const fileBuffer = await decryptState.file.arrayBuffer();
      const fileBytes = new Uint8Array(fileBuffer);

      // Validate Header
      const minHeaderLength = 4 + 1 + SALT_LENGTH + IV_LENGTH + 16; // minimum file length
      if (fileBytes.byteLength < minHeaderLength) {
        throw new Error('File is too short or not a valid THTD vault.');
      }

      // Check Magic 'THTD'
      const magic = String.fromCharCode(...fileBytes.slice(0, 4));
      if (magic !== 'THTD') {
        throw new Error('Invalid file format. Magic signature "THTD" not found.');
      }

      const version = fileBytes[4];
      if (version !== FORMAT_VERSION) {
        throw new Error(`Unsupported vault version: ${version}`);
      }

      const salt = fileBytes.slice(5, 5 + SALT_LENGTH);
      const iv = fileBytes.slice(5 + SALT_LENGTH, 5 + SALT_LENGTH + IV_LENGTH);
      const ciphertext = fileBytes.slice(5 + SALT_LENGTH + IV_LENGTH);

      // Collect 12 words
      const slotInputs = decWordsGrid.querySelectorAll('.slot-input');
      const words = Array.from(slotInputs).map(i => i.value.trim().toLowerCase());

      // Derive key via Argon2id
      const rawKey = await deriveArgon2Key(words, salt);
      const aesKey = await crypto.subtle.importKey(
        'raw',
        rawKey,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
      );

      // Decrypt with AES-GCM
      let decryptedBuffer;
      try {
        decryptedBuffer = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv },
          aesKey,
          ciphertext
        );
      } catch {
        throw new Error('Authentication failed: Incorrect 12 words or corrupted file.');
      }

      // Parse Metadata & Original File
      const decView = new DataView(decryptedBuffer);
      const metaLen = decView.getUint32(0, false); // big-endian
      const metaBytes = new Uint8Array(decryptedBuffer, 4, metaLen);
      const metaStr = new TextDecoder().decode(metaBytes);
      const metadata = JSON.parse(metaStr);

      const originalFileBytes = new Uint8Array(decryptedBuffer, 4 + metaLen);
      const restoredBlob = new Blob([originalFileBytes], { type: metadata.fileType });

      decryptState.decryptedBlob = restoredBlob;
      decryptState.originalName = metadata.fileName || 'restored_file';

      // Update UI
      resFilename.textContent = metadata.fileName;
      resFilesize.textContent = formatBytes(metadata.fileSize);
      resFiletype.textContent = metadata.fileType;
      resTimestamp.textContent = new Date(metadata.timestamp).toLocaleString();

      if (metadata.message && metadata.message.trim()) {
        resNoteText.textContent = metadata.message;
        resNoteContainer.classList.remove('hidden');
      } else {
        resNoteContainer.classList.add('hidden');
      }

      lblDownloadDecrypted.textContent = `Download ${metadata.fileName}`;

      decProcessing.classList.add('hidden');
      decResult.classList.remove('hidden');
      showToast('File decrypted and verified!', 'success');

    } catch (err) {
      console.error(err);
      decProcessing.classList.add('hidden');
      document.getElementById('decrypt-form').classList.remove('hidden');
      showToast(err.message, 'error');
    }
  });

  btnDownloadDecrypted.addEventListener('click', () => {
    if (!decryptState.decryptedBlob) return;
    triggerDownload(decryptState.decryptedBlob, decryptState.originalName);
  });

  btnDecryptAnother.addEventListener('click', () => {
    clearDecryptFile();
    decResult.classList.add('hidden');
    document.getElementById('decrypt-form').classList.remove('hidden');
  });

  // ==========================================
  // Helper: Trigger File Download
  // ==========================================
  function triggerDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 100);
  }

  // ==========================================
  // Initialization
  // ==========================================
  function printAsciiBanner() {
    console.log(
      `%c
████████╗██╗  ██╗████████╗██████╗ 
╚══██╔══╝██║  ██║╚══██╔══╝██╔══██╗
   ██║   ███████║   ██║   ██║  ██║
   ██║   ██╔══██║   ██║   ██║  ██║
   ██║   ██║  ██║   ██║   ██████╔╝
   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═════╝ 
  TOO HARD TO DECRYPT // v2.4
  Zero-Knowledge Client-Side Cryptographic Vault
  Cipher: AES-256-GCM | KDF: Argon2id (64MB) | Entropy: BIP-39 (128-bit)
  Security: > 10¹⁹ Years Brute-Force Resistance
`,
      'color: #d4ff00; font-family: monospace; font-weight: bold;'
    );
  }

  function init() {
    printAsciiBanner();
    setupEncryptDropZone();
    setupDecryptInputs();
  }

  // Run on DOM Ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
