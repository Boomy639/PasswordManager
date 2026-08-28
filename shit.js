document.addEventListener("DOMContentLoaded", async () => {
	const appShell = document.querySelector("#app-shell");
	const sidebarToggle = document.querySelector("#sidebar-toggle");
	const sidebarHandle = document.querySelector("#sidebar-handle");
	const tabs = document.querySelectorAll(".nav-tab");
	const panels = document.querySelectorAll(".tab-panel");
	const passwordForm = document.querySelector("#password-form");
	const passwordList = document.querySelector(".password-list");
	const vaultCount = document.querySelector(".vault-count");
	const exportButton = document.querySelector("#export-passwords");
	const importButton = document.querySelector("#import-passwords");
	const deleteAllButton = document.querySelector("#delete-all-passwords");
	const csvFileInput = document.querySelector("#csv-file");
	const importStatus = document.querySelector("#import-status");
	const themeSelect = document.querySelector("#theme-select");
	const themeStyleSelect = document.querySelector("#theme-style-select");
	const pinAction = document.querySelector("#pin-action");
	const pinForm = document.querySelector("#pin-form");
	const currentPinLabel = document.querySelector("#current-pin-label");
	const currentPinInput = document.querySelector("#current-pin");
	const newPinInput = document.querySelector("#new-pin");
	const confirmPinInput = document.querySelector("#confirm-pin");
	const pinStatus = document.querySelector("#pin-status");
	const cancelPin = document.querySelector("#cancel-pin");
	const vaultLock = document.querySelector("#vault-lock");
	const unlockForm = document.querySelector("#unlock-form");
	const unlockPinInput = document.querySelector("#unlock-pin");
	const unlockStatus = document.querySelector("#unlock-status");
	const storageKey = "password-manager-entries";
	const themeStorageKey = "password-manager-theme";
	const themeStyleStorageKey = "password-manager-theme-style";
	const pinStorageKey = "password-manager-pin";
	const encryptionSaltKey = "password-manager-encryption-salt";
	const defaultPin = "1111";
	const lockDelay = 5 * 60 * 1000;
	const vaultVersion = 1;
	const textEncoder = new TextEncoder();
	const textDecoder = new TextDecoder();
	let savedPasswords = [];
	let savedPin = localStorage.getItem(pinStorageKey);
	if (!savedPin) {
		savedPin = defaultPin;
		localStorage.setItem(pinStorageKey, savedPin);
	}

	const toBase64 = (bytes) => btoa(String.fromCharCode(...bytes));
	const fromBase64 = (value) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));

	const getStoredValue = (key) => {
		try {
			return localStorage.getItem(key);
		} catch {
			return null;
		}
	};

	const setStoredValue = (key, value) => {
		try {
			localStorage.setItem(key, value);
		} catch {
			// Ignore storage write failures so the app still works in locked-down environments.
		}
	};

	const deriveKey = async (passphrase, saltBytes) => {
		const keyMaterial = await crypto.subtle.importKey("raw", textEncoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
		return crypto.subtle.deriveKey(
			{ name: "PBKDF2", salt: saltBytes, iterations: 120000, hash: "SHA-256" },
			keyMaterial,
			{ name: "AES-GCM", length: 256 },
			false,
			["encrypt", "decrypt"]
		);
	};

	const getOrCreateEncryptionSalt = () => {
		let salt = getStoredValue(encryptionSaltKey);
		if (!salt) {
			salt = toBase64(crypto.getRandomValues(new Uint8Array(16)));
			setStoredValue(encryptionSaltKey, salt);
		}
		return fromBase64(salt);
	};

	const encryptVault = async (vaultData, passphrase) => {
		const saltBytes = getOrCreateEncryptionSalt();
		const key = await deriveKey(passphrase, saltBytes);
		const iv = crypto.getRandomValues(new Uint8Array(12));
		const encrypted = await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv },
			key,
			textEncoder.encode(JSON.stringify(vaultData))
		);
		return JSON.stringify({
			version: vaultVersion,
			salt: toBase64(saltBytes),
			iv: toBase64(iv),
			data: toBase64(new Uint8Array(encrypted))
		});
	};

	const decryptVault = async (vaultPayload, passphrase) => {
		const parsed = typeof vaultPayload === "string" ? JSON.parse(vaultPayload) : vaultPayload;
		if (!parsed || !parsed.data || !parsed.iv) {
			throw new Error("Vault payload is missing encrypted data.");
		}
		const saltBytes = fromBase64(parsed.salt || toBase64(getOrCreateEncryptionSalt()));
		const key = await deriveKey(passphrase, saltBytes);
		const decrypted = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: fromBase64(parsed.iv) },
			key,
			fromBase64(parsed.data)
		);
		return JSON.parse(textDecoder.decode(decrypted));
	};

	const loadPasswords = async () => {
		const rawVault = getStoredValue(storageKey);
		if (!rawVault) {
			savedPasswords = [];
			return;
		}

		try {
			const parsedVault = JSON.parse(rawVault);
			if (Array.isArray(parsedVault)) {
				savedPasswords = parsedVault;
				await persistPasswords();
				return;
			}
			if (parsedVault && parsedVault.version === vaultVersion && parsedVault.data && parsedVault.iv) {
				savedPasswords = await decryptVault(parsedVault, savedPin);
				if (!Array.isArray(savedPasswords)) savedPasswords = [];
				return;
			}
		} catch {
			// Fall back to plain text if the stored payload is older or invalid.
		}

		try {
			savedPasswords = JSON.parse(rawVault);
			if (!Array.isArray(savedPasswords)) savedPasswords = [];
			await persistPasswords();
		} catch {
			savedPasswords = [];
		}
	};

	const savedTheme = localStorage.getItem(themeStorageKey) || "espresso";
	const savedThemeStyle = localStorage.getItem(themeStyleStorageKey) || "classic";
	document.body.dataset.theme = savedTheme;
	document.body.dataset.themeStyle = savedThemeStyle;
	themeSelect.value = savedTheme;
	themeStyleSelect.value = savedThemeStyle;
	let inactivityTimer;
	let isLocked = false;
	currentPinLabel.hidden = !savedPin;
	pinAction.textContent = savedPin ? "Edit PIN" : "Create PIN";

	const setSidebarState = (state) => {
		const nextState = state === "hidden" ? "hidden" : "open";
		appShell.dataset.sidebarState = nextState;
		sidebarToggle.setAttribute("aria-expanded", String(nextState === "open"));
		sidebarToggle.setAttribute("aria-label", nextState === "open" ? "Hide sidebar" : "Show sidebar");
		sidebarToggle.title = nextState === "open" ? "Hide sidebar" : "Show sidebar";
		sidebarToggle.innerHTML = nextState === "open" ? "<span aria-hidden=\"true\">&#171;</span>" : "<span aria-hidden=\"true\">&#9776;</span>";
		sidebarHandle.hidden = nextState === "open";
	};

	const lockVault = () => {
		if (!savedPin || isLocked) return;
		isLocked = true;
		vaultLock.hidden = false;
		unlockPinInput.value = "";
		unlockStatus.textContent = "";
		unlockPinInput.focus();
	};

	const resetInactivityTimer = () => {
		clearTimeout(inactivityTimer);
		if (savedPin && !isLocked) inactivityTimer = setTimeout(lockVault, lockDelay);
	};

	if (savedPin) {
		isLocked = true;
		vaultLock.hidden = false;
		unlockPinInput.focus();
	}

	const showTab = (selectedTab) => {
		tabs.forEach((tab) => {
			const isSelected = tab.dataset.tab === selectedTab;
			tab.classList.toggle("is-active", isSelected);
			tab.setAttribute("aria-selected", String(isSelected));
		});

		panels.forEach((panel) => {
			const isSelected = panel.dataset.panel === selectedTab;
			panel.hidden = !isSelected;
			panel.classList.toggle("is-visible", isSelected);
		});
	};

	const updateEmptyState = () => {
		if (savedPasswords.length === 0 && !passwordList.querySelector(".empty-state")) {
			const emptyState = document.createElement("p");
			emptyState.className = "empty-state";
			emptyState.textContent = "Your vault is empty. Add your first password to get started.";
			passwordList.append(emptyState);
		}
	};

	const updateCount = () => {
		vaultCount.textContent = `${savedPasswords.length} SAVED`;
	};

	const persistPasswords = async () => {
		setStoredValue(storageKey, await encryptVault(savedPasswords, savedPin));
	};

	const parseCsv = (csv) => {
		const rows = [];
		let row = [];
		let field = "";
		let insideQuotes = false;

		for (let index = 0; index < csv.length; index += 1) {
			const character = csv[index];
			const nextCharacter = csv[index + 1];
			if (character === '"' && insideQuotes && nextCharacter === '"') {
				field += '"';
				index += 1;
			} else if (character === '"') {
				insideQuotes = !insideQuotes;
			} else if (character === "," && !insideQuotes) {
				row.push(field);
				field = "";
			} else if ((character === "\n" || character === "\r") && !insideQuotes) {
				if (character === "\r" && nextCharacter === "\n") index += 1;
				row.push(field);
				if (row.some((value) => value.trim())) rows.push(row);
				row = [];
				field = "";
			} else {
				field += character;
			}
		}
		if (field || row.length) {
			row.push(field);
			if (row.some((value) => value.trim())) rows.push(row);
		}
		return rows;
	};

	const importCsv = (csv) => {
		const rows = parseCsv(csv);
		if (rows.length < 2) return { imported: 0, skipped: 0 };
		const headers = rows[0].map((header) => header.trim().toLowerCase());
		const websiteIndex = headers.findIndex((header) => ["url", "website", "name", "login_uri"].includes(header));
		const usernameIndex = headers.findIndex((header) => ["username", "user", "login_username"].includes(header));
		const passwordIndex = headers.findIndex((header) => ["password", "login_password"].includes(header));
		if (websiteIndex < 0 || usernameIndex < 0 || passwordIndex < 0) return { imported: 0, skipped: rows.length - 1 };

		let imported = 0;
		let skipped = 0;
		rows.slice(1).forEach((row) => {
			const website = (row[websiteIndex] || "").trim();
			const username = (row[usernameIndex] || "").trim();
			const password = row[passwordIndex] || "";
			if (!website || !username || !password) {
				skipped += 1;
				return;
			}
			savedPasswords.push({ website, username, password });
			imported += 1;
		});
		return { imported, skipped };
	};

	const createPasswordCard = (entry, index) => {
		const card = document.createElement("article");
		card.className = "password-card";
		card.dataset.index = index;
		card.innerHTML = `<span class="site-icon"></span><div><h3></h3><p></p></div><div class="card-actions"><button class="icon-button copy-button" type="button" aria-label="Copy password">&#128203;</button><button class="icon-button remove-button" type="button" aria-label="Remove password">&#128465;</button></div>`;
		card.querySelector(".site-icon").textContent = entry.website.charAt(0).toUpperCase();
		card.querySelector("h3").textContent = entry.website;
		card.querySelector("p").textContent = entry.username;
		card.querySelector(".copy-button").addEventListener("click", async () => {
			await navigator.clipboard.writeText(entry.password);
		});
		card.querySelector(".remove-button").addEventListener("click", async () => {
			savedPasswords.splice(Number(card.dataset.index), 1);
			await persistPasswords();
			renderPasswords();
		});
		return card;
	};

	const renderPasswords = () => {
		passwordList.replaceChildren();
		savedPasswords.forEach((entry, index) => passwordList.append(createPasswordCard(entry, index)));
		updateCount();
		updateEmptyState();
	};

	sidebarToggle.addEventListener("click", () => {
		const currentState = appShell.dataset.sidebarState || "open";
		setSidebarState(currentState === "open" ? "hidden" : "open");
	});

	sidebarHandle.addEventListener("click", () => {
		setSidebarState("open");
	});

	tabs.forEach((tab) => {
		tab.addEventListener("click", () => {
			showTab(tab.dataset.tab);
		});
	});

	passwordForm.addEventListener("submit", async (event) => {
		event.preventDefault();
		const formData = new FormData(passwordForm);
		const website = formData.get("website").trim();
		const username = formData.get("username").trim();
		const password = formData.get("password");
		savedPasswords.push({ website, username, password });
		await persistPasswords();
		renderPasswords();
		passwordForm.reset();
		passwordForm.querySelector(".form-status").textContent = "Password saved.";
		showTab("passwords");
	});

	exportButton.addEventListener("click", () => {
		const text = savedPasswords.map((entry) => `Website: ${entry.website}\nUsername: ${entry.username}\nPassword: ${entry.password}\n`).join("\n");
		const download = document.createElement("a");
		download.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
		download.download = "passwords.txt";
		download.click();
		URL.revokeObjectURL(download.href);
	});

	importButton.addEventListener("click", () => csvFileInput.click());

	csvFileInput.addEventListener("change", async () => {
		const file = csvFileInput.files[0];
		if (!file) return;
		const result = importCsv(await file.text());
		await persistPasswords();
		renderPasswords();
		importStatus.textContent = `${result.imported} imported, ${result.skipped} skipped.`;
		csvFileInput.value = "";
	});

	deleteAllButton.addEventListener("click", async () => {
		if (savedPasswords.length === 0) return;
		if (!window.confirm("Delete all saved passwords? This cannot be undone.")) return;
		savedPasswords = [];
		await persistPasswords();
		renderPasswords();
	});

	themeSelect.addEventListener("change", () => {
		document.body.dataset.theme = themeSelect.value;
		localStorage.setItem(themeStorageKey, themeSelect.value);
	});

	themeStyleSelect.addEventListener("change", () => {
		document.body.dataset.themeStyle = themeStyleSelect.value;
		localStorage.setItem(themeStyleStorageKey, themeStyleSelect.value);
	});

	pinAction.addEventListener("click", () => {
		pinForm.hidden = false;
		currentPinLabel.hidden = !savedPin;
		pinStatus.textContent = "";
		newPinInput.focus();
	});

	cancelPin.addEventListener("click", () => {
		pinForm.reset();
		pinForm.hidden = true;
		pinStatus.textContent = "";
	});

	pinForm.addEventListener("submit", async (event) => {
		event.preventDefault();
		const newPin = newPinInput.value;
		if (!/^\d{4}$/.test(newPin) || newPin !== confirmPinInput.value) {
			pinStatus.textContent = "PIN must be four matching numbers.";
			return;
		}
		if (savedPin && currentPinInput.value !== savedPin) {
			pinStatus.textContent = "Current PIN is incorrect.";
			return;
		}
		savedPin = newPin;
		localStorage.setItem(pinStorageKey, savedPin);
		await persistPasswords();
		currentPinLabel.hidden = false;
		pinAction.textContent = "Edit PIN";
		pinForm.reset();
		pinForm.hidden = true;
		pinStatus.textContent = "PIN saved.";
		resetInactivityTimer();
	});

	unlockForm.addEventListener("submit", (event) => {
		event.preventDefault();
		if (!/^\d{4}$/.test(unlockPinInput.value) || unlockPinInput.value !== savedPin) {
			unlockStatus.textContent = "Incorrect PIN.";
			unlockPinInput.select();
			return;
		}
		isLocked = false;
		vaultLock.hidden = true;
		resetInactivityTimer();
	});

	document.addEventListener("pointerdown", resetInactivityTimer);
	document.addEventListener("keydown", resetInactivityTimer);
	await loadPasswords();
	setSidebarState("open");
	renderPasswords();
	resetInactivityTimer();
});
