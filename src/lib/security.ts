import type { D1Database } from "@cloudflare/workers-types";

// 1. Sanitasi String (Anti-XSS & Control Character Removal)
export function sanitizeText(input: string, maxLength: number): string {
	if (typeof input !== "string") return "";
	return input
		.replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g, "") // Strip non-printable control characters (keep \n \t)
		.replace(/<[^>]*>?/gm, "") // Strip HTML tags
		.replace(/javascript:/gi, "")
		.replace(/data:/gi, "")
		.trim()
		.slice(0, maxLength);
}

// 2. Constant-Time String Comparison (Anti-Timing Attacks)
export function timingSafeEqual(a: string, b: string): boolean {
	if (typeof a !== "string" || typeof b !== "string") return false;
	const aLen = a.length;
	const bLen = b.length;
	let diff = aLen ^ bLen;
	const maxLen = Math.max(aLen, bLen);
	for (let i = 0; i < maxLen; i++) {
		const charA = i < aLen ? a.charCodeAt(i) : 0;
		const charB = i < bLen ? b.charCodeAt(i) : 0;
		diff |= charA ^ charB;
	}
	return diff === 0;
}

// 3. Hash Session Token (Menghindari Menyimpan Plaintext Master Passcode di Cookie)
export async function createSessionToken(secret: string): Promise<string> {
	const msgBuffer = new TextEncoder().encode(`admin_auth_v1_session:${secret}`);
	const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
	return Array.from(new Uint8Array(hashBuffer))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

// 4. Secure Slug Generator (Anti-IDOR & Anti-Guessing Tamu)
export function generateSecureSlug(name: string): string {
	const base = name
		.toLowerCase()
		.trim()
		.replace(/\s+/g, "-")
		.replace(/[^\w\-]+/g, "")
		.replace(/\-\-+/g, "-")
		.slice(0, 35) || "tamu";

	const randomBytes = new Uint8Array(4);
	crypto.getRandomValues(randomBytes);
	const suffix = Array.from(randomBytes, (b) => b.toString(36).padStart(2, "0"))
		.join("")
		.slice(0, 6);

	return `${base}-${suffix}`;
}

// 5. Hash IP (GDPR / Data Privacy compliance)
export async function hashIp(ip: string, salt = "wedding_rsvp_secure_salt_2026"): Promise<string> {
	const msgBuffer = new TextEncoder().encode(`${salt}:${ip}`);
	const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
	return Array.from(new Uint8Array(hashBuffer))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

// 6. Verifikasi Cloudflare Turnstile
export async function verifyTurnstileToken(
	token: string,
	secretKey: string,
	ip?: string,
): Promise<{ success: boolean; error?: string }> {
	if (!token) {
		return { success: false, error: "Turnstile token wajib disertakan." };
	}

	const formData = new FormData();
	formData.append("secret", secretKey);
	formData.append("response", token);
	if (ip) {
		formData.append("remoteip", ip);
	}

	try {
		const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
			method: "POST",
			body: formData,
		});
		const outcome = (await res.json()) as { success: boolean; "error-codes"?: string[] };
		return {
			success: Boolean(outcome.success),
			error: outcome.success
				? undefined
				: outcome["error-codes"]?.join(", ") || "Verifikasi Turnstile gagal.",
		};
	} catch {
		return { success: false, error: "Gagal memverifikasi Turnstile ke server Cloudflare." };
	}
}

// 7. Atomic Rate Limiting via Cloudflare D1 (Anti-Race Condition & Auto Storage Cleanup)
export async function checkRateLimit(
	db: D1Database,
	ipHash: string,
	limit = 5,
	windowSeconds = 600,
): Promise<boolean> {
	const now = Math.floor(Date.now() / 1000);

	// Jalankan atomic UPSERT di D1
	const upsertRes = await db
		.prepare(
			`INSERT INTO rsvp_rate_limits (ip_hash, attempts, first_attempt_at, last_attempt_at)
			 VALUES (?1, 1, ?2, ?2)
			 ON CONFLICT(ip_hash) DO UPDATE SET
				attempts = CASE
					WHEN ?2 - first_attempt_at > ?3 THEN 1
					ELSE attempts + 1
				END,
				first_attempt_at = CASE
					WHEN ?2 - first_attempt_at > ?3 THEN ?2
					ELSE first_attempt_at
				END,
				last_attempt_at = ?2
			 RETURNING attempts`,
		)
		.bind(ipHash, now, windowSeconds)
		.first<{ attempts: number }>();

	// Bersihkan record kedaluwarsa secara berkala (5% probabilitas setiap request) agar D1 storage tidak membengkak
	if (Math.random() < 0.05) {
		const staleThreshold = now - windowSeconds * 2;
		db.prepare("DELETE FROM rsvp_rate_limits WHERE last_attempt_at < ?")
			.bind(staleThreshold)
			.run()
			.catch(() => {});
	}

	if (!upsertRes || typeof upsertRes.attempts !== "number") {
		return true;
	}

	return upsertRes.attempts <= limit;
}
