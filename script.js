// Password Security Suite - Main JavaScript File
class PasswordSecuritySuite {
    constructor() {
        this.passwords = JSON.parse(localStorage.getItem('passwords') || '[]');
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.renderPasswordList();
        this.updateLengthDisplay();
        this.applySavedPreferences && this.applySavedPreferences();
        this.maybeShowOnboarding && this.maybeShowOnboarding();
    }

    setupEventListeners() {
        // Tab navigation
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
        });

        // Quick actions (theme, density, onboarding) and keyboard shortcuts
        const openOnboardingBtn = document.getElementById('openOnboarding');
        if (openOnboardingBtn) openOnboardingBtn.addEventListener('click', () => this.showOnboarding());

        // Password strength analyzer
        const passwordInput = document.getElementById('passwordInput');
        const toggleVisibility = document.getElementById('toggleVisibility');
        
        passwordInput.addEventListener('input', (e) => this.analyzePassword(e.target.value));
        toggleVisibility.addEventListener('click', () => this.togglePasswordVisibility('passwordInput'));

        // Password generator
        const lengthSlider = document.getElementById('lengthSlider');
        const generateBtn = document.getElementById('generateNew');
        const copyBtn = document.getElementById('copyPassword');
        const generatedPassword = document.getElementById('generatedPassword');
        const modeSelect = document.getElementById('modeSelect');

        lengthSlider.addEventListener('input', (e) => this.updateLengthDisplay(e.target.value));
        generateBtn.addEventListener('click', () => this.generatePassword());
        copyBtn.addEventListener('click', () => this.copyToClipboard(generatedPassword.value));
        if (modeSelect) {
            modeSelect.addEventListener('change', () => this.updateGeneratorMode());
        }

        // Check all generator checkboxes for changes
        document.querySelectorAll('#generator input[type="checkbox"]').forEach(checkbox => {
            checkbox.addEventListener('change', () => this.generatePassword());
        });

        // Generator options inputs
        ['passphraseWordCount','passphraseSeparator','passphraseCase','pronounceableSyllables','templatePattern']
            .forEach(id => {
                const el = document.getElementById(id);
                if (el) el.addEventListener('input', () => this.generatePassword());
            });

        // Breach checker
        const breachPasswordInput = document.getElementById('breachPasswordInput');
        const checkBreachBtn = document.getElementById('checkBreach');

        checkBreachBtn.addEventListener('click', () => this.checkPasswordBreach(breachPasswordInput.value));

        // Password manager
        const addPasswordBtn = document.getElementById('addPassword');
        const savePasswordBtn = document.getElementById('savePassword');
        const cancelAddBtn = document.getElementById('cancelAdd');
        const closeModalBtn = document.getElementById('closeModal');
        const exportBtn = document.getElementById('exportPasswords');
        const importBtn = document.getElementById('importPasswords');
        const importFile = document.getElementById('importFile');

        addPasswordBtn.addEventListener('click', () => this.showAddPasswordModal());
        savePasswordBtn.addEventListener('click', () => this.savePassword());
        cancelAddBtn.addEventListener('click', () => this.hideAddPasswordModal());
        closeModalBtn.addEventListener('click', () => this.hideAddPasswordModal());
        exportBtn.addEventListener('click', () => this.exportPasswords());
        importBtn.addEventListener('click', () => importFile.click());
        importFile.addEventListener('change', (e) => this.importPasswords(e.target.files[0]));

        // Modal password visibility toggle
        const togglePasswordVisibilityBtn = document.getElementById('togglePasswordVisibility');
        togglePasswordVisibilityBtn.addEventListener('click', () => this.togglePasswordVisibility('password'));

        // Settings
        const saveSettingsBtn = document.getElementById('saveSettings');
        if (saveSettingsBtn) {
            saveSettingsBtn.addEventListener('click', () => this.saveSettings());
        }

        // Generate initial password
        this.generatePassword();
    }

    // Tab Management
    switchTab(tabName) {
        // Hide all tab contents
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });

        // Remove active class from all tabs
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.remove('active');
        });

        // Show selected tab content
        document.getElementById(tabName).classList.add('active');
        
        // Add active class to clicked tab
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    }

    // Password Strength Analyzer
    analyzePassword(password) {
        if (!password) {
            this.resetStrengthDisplay();
            return;
        }

        const entropy = this.calculateEntropy(password);
        const strength = this.getStrengthLevel(entropy);
        const crackTime = this.calculateCrackTime(entropy);
        const checks = this.performSecurityChecks(password);

        this.updateStrengthDisplay(strength, entropy, password.length, crackTime);
        this.updateSecurityChecks(checks);
    }

    calculateEntropy(password) {
        let charset = 0;
        if (/[a-z]/.test(password)) charset += 26;
        if (/[A-Z]/.test(password)) charset += 26;
        if (/[0-9]/.test(password)) charset += 10;
        if (/[^a-zA-Z0-9]/.test(password)) charset += 32; // Common special chars

        return Math.log2(Math.pow(charset, password.length));
    }

    getStrengthLevel(entropy) {
        if (entropy < 30) return 'weak';
        if (entropy < 50) return 'fair';
        if (entropy < 70) return 'good';
        return 'strong';
    }

    calculateCrackTime(entropy) {
        const attemptsPerSecond = 1000000000; // 1 billion attempts per second
        const totalCombinations = Math.pow(2, entropy);
        const seconds = totalCombinations / attemptsPerSecond;

        if (seconds < 1) return 'Instant';
        if (seconds < 60) return `${Math.round(seconds)} seconds`;
        if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
        if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
        if (seconds < 31536000000) return `${Math.round(seconds / 31536000)} years`;
        return `${Math.round(seconds / 31536000000)} centuries`;
    }

    performSecurityChecks(password) {
        return {
            length: password.length >= 12,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            numbers: /[0-9]/.test(password),
            symbols: /[^a-zA-Z0-9]/.test(password),
            patterns: !this.hasCommonPatterns(password)
        };
    }

    hasCommonPatterns(password) {
        const commonPatterns = [
            /123/,
            /abc/,
            /qwe/,
            /password/i,
            /admin/i,
            /user/i,
            /login/i,
            /(.)\1{2,}/, // Repeated characters
            /(.)(.)\1\2/, // Alternating patterns
        ];
        return commonPatterns.some(pattern => pattern.test(password));
    }

    updateStrengthDisplay(strength, entropy, length, crackTime) {
        const strengthFill = document.getElementById('strengthFill');
        const strengthText = document.getElementById('strengthText');
        const entropyScore = document.getElementById('entropyScore');
        const charCount = document.getElementById('charCount');
        const crackTimeEl = document.getElementById('crackTime');

        strengthFill.className = `strength-fill ${strength}`;
        strengthText.textContent = strength.toUpperCase();
        entropyScore.textContent = Math.round(entropy);
        charCount.textContent = length;
        crackTimeEl.textContent = crackTime;
    }

    updateSecurityChecks(checks) {
        Object.keys(checks).forEach(key => {
            const checkElement = document.getElementById(`${key}Check`);
            const icon = checkElement.querySelector('i');
            
            if (checks[key]) {
                icon.className = 'fas fa-check';
                checkElement.style.color = '#00ff88';
            } else {
                icon.className = 'fas fa-times';
                checkElement.style.color = '#ff4444';
            }
        });
    }

    resetStrengthDisplay() {
        const strengthFill = document.getElementById('strengthFill');
        const strengthText = document.getElementById('strengthText');
        const entropyScore = document.getElementById('entropyScore');
        const charCount = document.getElementById('charCount');
        const crackTimeEl = document.getElementById('crackTime');

        strengthFill.className = 'strength-fill';
        strengthFill.style.width = '0%';
        strengthText.textContent = 'Enter a password';
        entropyScore.textContent = '0';
        charCount.textContent = '0';
        crackTimeEl.textContent = 'Instant';

        // Reset all checks
        document.querySelectorAll('.check-item i').forEach(icon => {
            icon.className = 'fas fa-times';
        });
        document.querySelectorAll('.check-item').forEach(item => {
            item.style.color = '#ff4444';
        });
    }

    // Password Generator
    generatePassword() {
        const modeSelect = document.getElementById('modeSelect');
        const mode = modeSelect ? modeSelect.value : 'random';
        const length = parseInt(document.getElementById('lengthSlider').value);
        if (mode === 'passphrase') {
            const words = parseInt(document.getElementById('passphraseWordCount').value || '5');
            const sep = (document.getElementById('passphraseSeparator').value || '-').slice(0,3);
            const casing = document.getElementById('passphraseCase').value || 'title';
            const pass = this.generatePassphrase(words, sep, casing);
            document.getElementById('generatedPassword').value = pass;
            this.updateGeneratedPasswordStats(pass);
            return;
        }
        if (mode === 'pronounceable') {
            const syllables = parseInt(document.getElementById('pronounceableSyllables').value || '6');
            const pass = this.generatePronounceable(syllables);
            document.getElementById('generatedPassword').value = pass;
            this.updateGeneratedPasswordStats(pass);
            return;
        }
        if (mode === 'template') {
            const pattern = document.getElementById('templatePattern').value || 'Cvcv-####';
            const pass = this.generateFromTemplate(pattern);
            document.getElementById('generatedPassword').value = pass;
            this.updateGeneratedPasswordStats(pass);
            return;
        }
        const includeUppercase = document.getElementById('includeUppercase').checked;
        const includeLowercase = document.getElementById('includeLowercase').checked;
        const includeNumbers = document.getElementById('includeNumbers').checked;
        const includeSymbols = document.getElementById('includeSymbols').checked;
        const excludeSimilar = document.getElementById('excludeSimilar').checked;
        const excludeAmbiguous = document.getElementById('excludeAmbiguous').checked;
        const enforceAllSets = document.getElementById('enforceAllSets')?.checked;
        const avoidRuns = document.getElementById('avoidRuns')?.checked;

        let charset = '';
        if (includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
        if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (includeNumbers) charset += '0123456789';
        if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

        if (excludeSimilar) {
            charset = charset.replace(/[0O1lI]/g, '');
        }

        if (excludeAmbiguous) {
            charset = charset.replace(/[{}[\]\\|;:,.<>]/g, '');
        }

        if (charset.length === 0) {
            alert('Please select at least one character type.');
            return;
        }

        let password = '';
        const pick = () => charset.charAt(Math.floor(Math.random() * charset.length));
        if (enforceAllSets) {
            const parts = [];
            if (includeLowercase) parts.push(this.randomFrom('abcdefghijklmnopqrstuvwxyz'));
            if (includeUppercase) parts.push(this.randomFrom('ABCDEFGHIJKLMNOPQRSTUVWXYZ'));
            if (includeNumbers) parts.push(this.randomFrom('0123456789'));
            if (includeSymbols) parts.push(this.randomFrom('!@#$%^&*()_+-=[]{}|;:,.<>?'));
            while (parts.length < length) parts.push(pick());
            for (let i = parts.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [parts[i], parts[j]] = [parts[j], parts[i]];
            }
            password = parts.slice(0, length).join('');
        } else {
            for (let i = 0; i < length; i++) password += pick();
        }

        if (avoidRuns) password = this.removeRunsAndSequences(password, charset);

        document.getElementById('generatedPassword').value = password;
        this.updateGeneratedPasswordStats(password);
    }

    randomFrom(chars) {
        return chars.charAt(Math.floor(Math.random() * chars.length));
    }

    removeRunsAndSequences(pass, charset) {
        const arr = pass.split('');
        for (let i = 2; i < arr.length; i++) {
            const a = arr[i-2], b = arr[i-1], c = arr[i];
            const isSame = (x,y) => x === y;
            const isSeq = (x,y) => charset.indexOf(y) - charset.indexOf(x) === 1;
            if ((isSame(a,b) && isSame(b,c)) || (isSeq(a,b) && isSeq(b,c))) {
                arr[i] = this.randomFrom(charset);
                i = Math.max(1, i-2);
            }
        }
        return arr.join('');
    }

    generatePassphrase(words = 5, sep = '-', casing = 'title') {
        const wordlist = this.getWordlist();
        const pick = () => wordlist[Math.floor(Math.random() * wordlist.length)];
        const chosen = Array.from({ length: words }, pick).map(w => {
            if (casing === 'upper') return w.toUpperCase();
            if (casing === 'lower') return w.toLowerCase();
            return w.charAt(0).toUpperCase() + w.slice(1).toLowerCase();
        });
        return chosen.join(sep);
    }

    getWordlist() {
        // Common English words for Diceware-style passphrases
        return [
            'about', 'above', 'abuse', 'actor', 'acute', 'admit', 'adopt', 'adult', 'after', 'again',
            'agent', 'agree', 'ahead', 'alarm', 'album', 'alert', 'alien', 'align', 'alike', 'alive',
            'allow', 'alone', 'along', 'alter', 'among', 'anger', 'angle', 'angry', 'apart', 'apple',
            'apply', 'arena', 'argue', 'arise', 'array', 'aside', 'asset', 'avoid', 'awake', 'award',
            'aware', 'badly', 'basic', 'beach', 'began', 'begin', 'being', 'below', 'bench', 'billy',
            'birth', 'black', 'blame', 'blank', 'blind', 'block', 'blood', 'board', 'boost', 'booth',
            'bound', 'brain', 'brand', 'bread', 'break', 'breed', 'brief', 'bring', 'broad', 'broke',
            'brown', 'build', 'built', 'buyer', 'cable', 'calm', 'came', 'can', 'card', 'care',
            'case', 'cash', 'cast', 'cell', 'chart', 'check', 'chose', 'civil', 'claim', 'class',
            'clean', 'clear', 'click', 'climb', 'clock', 'close', 'cloud', 'coach', 'coast', 'could',
            'count', 'court', 'cover', 'craft', 'crash', 'crazy', 'cream', 'crime', 'cross', 'crowd',
            'crown', 'crude', 'curve', 'cycle', 'daily', 'dance', 'dated', 'dealt', 'death', 'debut',
            'delay', 'depth', 'doing', 'doubt', 'dozen', 'draft', 'drama', 'drank', 'dream', 'dress',
            'drill', 'drink', 'drive', 'drove', 'dying', 'eager', 'early', 'earth', 'eight', 'elite',
            'empty', 'enemy', 'enjoy', 'enter', 'entry', 'equal', 'error', 'event', 'every', 'exact',
            'exist', 'extra', 'faith', 'false', 'fault', 'fiber', 'field', 'fifth', 'fifty', 'fight',
            'final', 'first', 'fixed', 'flash', 'fleet', 'floor', 'fluid', 'focus', 'force', 'forth',
            'forty', 'forum', 'found', 'frame', 'frank', 'fraud', 'fresh', 'front', 'fruit', 'fully',
            'funny', 'giant', 'given', 'glass', 'globe', 'going', 'grace', 'grade', 'grand', 'grant',
            'grass', 'grave', 'great', 'green', 'gross', 'group', 'grown', 'guard', 'guess', 'guest',
            'guide', 'happy', 'harry', 'heart', 'heavy', 'might', 'minor', 'minus', 'mixed', 'model',
            'money', 'month', 'moral', 'motor', 'mount', 'mouse', 'mouth', 'moved', 'movie', 'music',
            'needs', 'never', 'newly', 'night', 'noise', 'north', 'noted', 'novel', 'nurse', 'occur',
            'ocean', 'offer', 'often', 'order', 'other', 'ought', 'paint', 'panel', 'paper', 'party',
            'peace', 'peter', 'phase', 'phone', 'photo', 'piece', 'pilot', 'pitch', 'place', 'plain',
            'plane', 'plant', 'plate', 'point', 'pound', 'power', 'press', 'price', 'pride', 'prime',
            'print', 'prior', 'prize', 'proof', 'proud', 'prove', 'queen', 'quick', 'quiet', 'quite',
            'radio', 'raise', 'range', 'rapid', 'ratio', 'reach', 'ready', 'realm', 'rebel', 'refer',
            'relax', 'reply', 'right', 'rigid', 'rival', 'river', 'robin', 'roger', 'roman', 'rough',
            'round', 'route', 'royal', 'rural', 'scale', 'scene', 'scope', 'score', 'sense', 'serve',
            'seven', 'shall', 'shape', 'share', 'sharp', 'sheet', 'shelf', 'shell', 'shift', 'shine',
            'shock', 'shoot', 'short', 'shown', 'sight', 'silly', 'since', 'sixth', 'sixty', 'sized',
            'skill', 'sleep', 'slide', 'small', 'smart', 'smile', 'smith', 'smoke', 'snake', 'snow',
            'solar', 'solid', 'solve', 'sorry', 'sound', 'south', 'space', 'spare', 'speak', 'speed',
            'spend', 'spent', 'split', 'spoke', 'sport', 'staff', 'stage', 'stake', 'stand', 'start',
            'state', 'steam', 'steel', 'steep', 'steer', 'steps', 'stick', 'still', 'stock', 'stone',
            'stood', 'store', 'storm', 'story', 'strip', 'stuck', 'study', 'stuff', 'style', 'sugar',
            'suite', 'super', 'sweet', 'table', 'taken', 'taste', 'taxes', 'teach', 'teeth', 'terry',
            'texas', 'thank', 'theft', 'their', 'theme', 'there', 'these', 'thick', 'thing', 'think',
            'third', 'those', 'three', 'threw', 'throw', 'thumb', 'tight', 'times', 'tired', 'title',
            'today', 'topic', 'total', 'touch', 'tough', 'tower', 'track', 'trade', 'train', 'treat',
            'trend', 'trial', 'tribe', 'trick', 'tried', 'tries', 'truck', 'truly', 'trust', 'truth',
            'twice', 'under', 'undue', 'union', 'unity', 'until', 'upper', 'upset', 'urban', 'usage',
            'usual', 'valid', 'value', 'video', 'virus', 'visit', 'vital', 'voice', 'waste', 'watch',
            'water', 'wheel', 'where', 'which', 'while', 'white', 'whole', 'whose', 'woman', 'women',
            'world', 'worry', 'worse', 'worst', 'worth', 'would', 'write', 'wrong', 'wrote', 'young',
            'youth'
        ];
    }

    generatePronounceable(syllables = 6) {
        const vowels = 'aeiou';
        const consonants = 'bcdfghjklmnpqrstvwxyz';
        let out = '';
        for (let i = 0; i < syllables; i++) {
            const c = this.randomFrom(consonants);
            const v = this.randomFrom(vowels);
            const maybe = Math.random() < 0.5 ? '' : this.randomFrom(consonants);
            out += c + v + maybe;
        }
        return out;
    }

    generateFromTemplate(pattern) {
        const vowels = 'aeiou';
        const lowers = 'abcdefghijklmnopqrstuvwxyz';
        const uppers = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const digits = '0123456789';
        const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        let out = '';
        for (const ch of pattern) {
            switch (ch) {
                case 'C': out += this.randomFrom(uppers); break;
                case 'c': out += this.randomFrom(lowers); break;
                case 'v': out += this.randomFrom(vowels); break;
                case '#': out += this.randomFrom(digits); break;
                case '*': out += this.randomFrom(symbols); break;
                default: out += ch; break;
            }
        }
        return out;
    }

    updateGeneratedPasswordStats(password) {
        const entropy = this.calculateEntropy(password);
        const strength = this.getStrengthLevel(entropy);

        document.getElementById('generatedEntropy').textContent = `${Math.round(entropy)} bits`;
        document.getElementById('generatedStrength').textContent = strength.toUpperCase();
    }

    updateLengthDisplay(value) {
        document.getElementById('lengthValue').textContent = value;
    }

    updateGeneratorMode() {
        const mode = document.getElementById('modeSelect').value;
        const map = { passphrase: 'passphraseOptions', pronounceable: 'pronounceableOptions', template: 'templateOptions' };
        ['passphraseOptions','pronounceableOptions','templateOptions'].forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            const show = map[mode] === id;
            el.classList.toggle('hidden', !show);
            el.setAttribute('aria-hidden', String(!show));
        });
        this.generatePassword();
    }

    // Breach Checker
    async checkPasswordBreach(password) {
        if (!password) {
            this.updateBreachResult('Enter a password to check for breaches', 'default');
            return;
        }

        this.updateBreachResult('Checking password...', 'checking');

        try {
            const hash = await this.sha1(password);
            const hashPrefix = hash.substring(0, 5);
            const hashSuffix = hash.substring(5);

            const response = await fetch(`https://api.pwnedpasswords.com/range/${hashPrefix}`);
            const data = await response.text();

            const isBreached = data.includes(hashSuffix.toUpperCase());
            
            if (isBreached) {
                const count = this.extractBreachCount(data, hashSuffix);
                this.updateBreachResult(`⚠️ This password has been found in ${count} data breaches!`, 'breached');
            } else {
                this.updateBreachResult('✅ This password has not been found in any known breaches.', 'safe');
            }
        } catch (error) {
            this.updateBreachResult('❌ Error checking password. Please try again.', 'breached');
        }
    }

    async sha1(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        const hashBuffer = await crypto.subtle.digest('SHA-1', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    }

    extractBreachCount(data, hashSuffix) {
        const lines = data.split('\n');
        for (const line of lines) {
            if (line.startsWith(hashSuffix.toUpperCase())) {
                return parseInt(line.split(':')[1]) || 0;
            }
        }
        return 0;
    }

    updateBreachResult(message, status) {
        const result = document.getElementById('breachResult');
        const statusEl = result.querySelector('.breach-status');
        
        statusEl.innerHTML = `<i class="fas fa-shield-alt"></i><span>${message}</span>`;
        statusEl.className = `breach-status ${status}`;
    }

    // Preferences, theme, density, onboarding
    applySavedPreferences() {
        const density = 'comfortable';
        document.body.classList.toggle('light', false);
        document.body.classList.toggle('compact', false);
    }

    // Keyboard shortcuts removed per user preference

    maybeShowOnboarding() {
        const dont = localStorage.getItem('dontShowOnboarding') === '1';
        if (!dont) this.showOnboarding();
        const close = () => this.hideOnboarding();
        document.getElementById('closeOnboarding')?.addEventListener('click', close);
        document.getElementById('closeOnboardingPrimary')?.addEventListener('click', () => {
            const chk = document.getElementById('dontShowOnboarding');
            if (chk && chk.checked) localStorage.setItem('dontShowOnboarding','1');
            this.hideOnboarding();
        });
    }

    showOnboarding() { document.getElementById('onboardingModal')?.classList.add('active'); }
    hideOnboarding() { document.getElementById('onboardingModal')?.classList.remove('active'); }

    // Settings
    saveSettings() {
        const lockTimeout = document.getElementById('lockTimeout').value;
        const defaultLength = document.getElementById('defaultLength').value;
        
        localStorage.setItem('lockTimeout', lockTimeout);
        localStorage.setItem('defaultLength', defaultLength);
        
        // Apply default length to generator
        document.getElementById('lengthSlider').value = defaultLength;
        document.getElementById('lengthValue').textContent = defaultLength;
        
        this.showNotification('Settings saved!', 'success');
    }

    // Password Manager
    showAddPasswordModal() {
        document.getElementById('addPasswordModal').classList.add('active');
        document.getElementById('siteName').focus();
    }

    hideAddPasswordModal() {
        document.getElementById('addPasswordModal').classList.remove('active');
        this.clearAddPasswordForm();
    }

    clearAddPasswordForm() {
        document.getElementById('siteName').value = '';
        document.getElementById('username').value = '';
        document.getElementById('password').value = '';
        document.getElementById('notes').value = '';
    }

    savePassword() {
        const siteName = document.getElementById('siteName').value.trim();
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const notes = document.getElementById('notes').value.trim();

        if (!siteName || !username || !password) {
            alert('Please fill in all required fields.');
            return;
        }

        const passwordEntry = {
            id: Date.now().toString(),
            siteName,
            username,
            password: this.encryptPassword(password),
            notes,
            createdAt: new Date().toISOString()
        };

        this.passwords.push(passwordEntry);
        this.savePasswordsToStorage();
        this.renderPasswordList();
        this.hideAddPasswordModal();
    }

    encryptPassword(password) {
        // Simple base64 encoding for demo purposes
        // In a real application, use proper encryption like AES
        return btoa(password);
    }

    decryptPassword(encryptedPassword) {
        // Simple base64 decoding for demo purposes
        try {
            return atob(encryptedPassword);
        } catch (e) {
            return 'Decryption Error';
        }
    }

    renderPasswordList() {
        const passwordList = document.getElementById('passwordList');
        
        if (this.passwords.length === 0) {
            passwordList.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-key"></i>
                    <h3>No passwords stored</h3>
                    <p>Add your first password to get started</p>
                </div>
            `;
            return;
        }

        passwordList.innerHTML = this.passwords.map(password => `
            <div class="password-item">
                <div class="password-item-header">
                    <h3 class="password-item-title">${this.escapeHtml(password.siteName)}</h3>
                    <div class="password-item-actions">
                        <button class="action-btn" onclick="passwordSuite.togglePasswordVisibility('${password.id}')" title="Show/Hide Password">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="action-btn" onclick="passwordSuite.copyPassword('${password.id}')" title="Copy Password">
                            <i class="fas fa-copy"></i>
                        </button>
                        <button class="action-btn" onclick="passwordSuite.deletePassword('${password.id}')" title="Delete Password">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
                <div class="password-item-details">
                    <div class="detail-item">
                        <span class="detail-label">Username/Email</span>
                        <span class="detail-value">${this.escapeHtml(password.username)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Password</span>
                        <span class="detail-value password-value" id="password-${password.id}">••••••••</span>
                    </div>
                    ${password.notes ? `
                    <div class="detail-item">
                        <span class="detail-label">Notes</span>
                        <span class="detail-value">${this.escapeHtml(password.notes)}</span>
                    </div>
                    ` : ''}
                </div>
            </div>
        `).join('');
    }

    togglePasswordVisibility(passwordId) {
        const passwordEl = document.getElementById(`password-${passwordId}`);
        const password = this.passwords.find(p => p.id === passwordId);
        
        if (!password) return;

        if (passwordEl.textContent === '••••••••') {
            passwordEl.textContent = this.decryptPassword(password.password);
        } else {
            passwordEl.textContent = '••••••••';
        }
    }

    copyPassword(passwordId) {
        const password = this.passwords.find(p => p.id === passwordId);
        if (password) {
            const decryptedPassword = this.decryptPassword(password.password);
            this.copyToClipboard(decryptedPassword);
        }
    }

    deletePassword(passwordId) {
        if (confirm('Are you sure you want to delete this password?')) {
            this.passwords = this.passwords.filter(p => p.id !== passwordId);
            this.savePasswordsToStorage();
            this.renderPasswordList();
        }
    }

    exportPasswords() {
        const dataStr = JSON.stringify(this.passwords, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `passwords-${new Date().toISOString().split('T')[0]}.json`;
        link.click();
        
        URL.revokeObjectURL(url);
    }

    importPasswords(file) {
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const importedPasswords = JSON.parse(e.target.result);
                if (Array.isArray(importedPasswords)) {
                    this.passwords = [...this.passwords, ...importedPasswords];
                    this.savePasswordsToStorage();
                    this.renderPasswordList();
                    alert(`Successfully imported ${importedPasswords.length} passwords.`);
                } else {
                    alert('Invalid file format.');
                }
            } catch (error) {
                alert('Error reading file. Please check the format.');
            }
        };
        reader.readAsText(file);
    }

    savePasswordsToStorage() {
        localStorage.setItem('passwords', JSON.stringify(this.passwords));
    }

    // Utility Functions
    togglePasswordVisibility(inputId) {
        const input = document.getElementById(inputId);
        const button = input.nextElementSibling || input.parentElement.querySelector('button');
        const icon = button.querySelector('i');
        
        if (input.type === 'password') {
            input.type = 'text';
            icon.className = 'fas fa-eye-slash';
        } else {
            input.type = 'password';
            icon.className = 'fas fa-eye';
        }
    }

    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            this.showNotification('Password copied to clipboard!', 'success');
        } catch (err) {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            this.showNotification('Password copied to clipboard!', 'success');
        }
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check' : 'info'}-circle"></i>
            <span>${message}</span>
        `;
        
        // Add styles
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${type === 'success' ? '#00ff88' : '#333'};
            color: ${type === 'success' ? '#000' : '#fff'};
            padding: 1rem 1.5rem;
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
            z-index: 10000;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            animation: slideIn 0.3s ease-out;
        `;
        
        document.body.appendChild(notification);
        
        // Remove after 3 seconds
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-in';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Add CSS for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// Initialize the application
const passwordSuite = new PasswordSecuritySuite();

// Register service worker for PWA
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('./sw.js').catch(() => {});
    });
}
