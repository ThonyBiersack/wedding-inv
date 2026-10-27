import type { D1Database } from "@cloudflare/workers-types";

// 1. Sanitasi String (Anti-XSS & HTML Injection)
export function sanitizeText(input: string, maxLength: number): string {
	return input
		.replace(/<[^>]*>/g, "") // Strip HTML tags
		.replace(/[\u0000-\u001F\u007F-\u009F]/g, "") // Strip control characters
		.trim()
		.slice(0, maxLength);
}

// 2. Hash IP (GDPR / Data Privacy compliance)
export async function hashIp(ip: string): Promise<string> {
	const msgBuffer = new TextEncoder().encode(ip + "_salt_rsvp");
	const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
	return Array.from(new Uint8Array(hashBuffer))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

// 3. Verifikasi Cloudflare Turnstile
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

// 4. Rate Limiting via D1 (Maksimal 5 submit per 10 menit)
export async function checkRateLimit(
	db: D1Database,
	ipHash: string,
	limit = 5,
	windowSeconds = 600,
): Promise<boolean> {
	const now = Math.floor(Date.now() / 1000);
	const windowStart = now - windowSeconds;

	const record = await db
		.prepare("SELECT attempts, first_attempt_at FROM rsvp_rate_limits WHERE ip_hash = ?")
		.bind(ipHash)
		.first<{ attempts: number; first_attempt_at: number }>();

	if (!record) {
		await db
			.prepare(
				"INSERT INTO rsvp_rate_limits (ip_hash, attempts, first_attempt_at, last_attempt_at) VALUES (?, 1, ?, ?)",
			)
			.bind(ipHash, now, now)
			.run();
		return true;
	}

	if (record.first_attempt_at < windowStart) {
		// Reset window
		await db
			.prepare(
				"UPDATE rsvp_rate_limits SET attempts = 1, first_attempt_at = ?, last_attempt_at = ? WHERE ip_hash = ?",
			)
			.bind(now, now, ipHash)
			.run();
		return true;
	}

	if (record.attempts >= limit) {
		return false;
	}

	await db
		.prepare(
			"UPDATE rsvp_rate_limits SET attempts = attempts + 1, last_attempt_at = ? WHERE ip_hash = ?",
		)
		.bind(now, ipHash)
		.run();

	return true;
}
