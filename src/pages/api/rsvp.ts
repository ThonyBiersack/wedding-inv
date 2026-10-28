import type { APIRoute } from "astro";
import { env } from "cloudflare:workers";
import { getDb } from "../../lib/db";
import { sanitizeText, hashIp, verifyTurnstileToken, checkRateLimit, getClientIp } from "../../lib/security";

export const prerender = false;

function getTurnstileSecret(): string | undefined {
	try {
		if (typeof env !== "undefined" && (env as any)?.TURNSTILE_SECRET_KEY) {
			return (env as any).TURNSTILE_SECRET_KEY;
		}
	} catch {}
	return (import.meta as any).env?.TURNSTILE_SECRET_KEY;
}

// GET: Ambil daftar ucapan (Terfilter & Terurut)
export const GET: APIRoute = async () => {
	try {
		const db = await getDb();
		if (!db) {
			return new Response(
				JSON.stringify({ error: "D1 Database binding tidak ditemukan." }),
				{ status: 500, headers: { "Content-Type": "application/json" } },
			);
		}

		const { results } = await db
			.prepare(
				"SELECT id, name, status_rsvp, wishes, created_at FROM guests WHERE wishes IS NOT NULL AND trim(wishes) != '' ORDER BY id DESC LIMIT 50",
			)
			.all();

		return new Response(JSON.stringify(results ?? []), {
			status: 200,
			headers: {
				"Content-Type": "application/json",
				"Cache-Control": "public, max-age=15, s-maxage=30",
			},
		});
	} catch (error: unknown) {
		const message = error instanceof Error ? error.message : "Terjadi kesalahan server";
		return new Response(JSON.stringify({ error: message }), {
			status: 500,
			headers: { "Content-Type": "application/json" },
		});
	}
};

// POST: Submit RSVP & Doa dengan Verifikasi Keamanan Penuh
export const POST: APIRoute = async ({ request, clientAddress }) => {
	try {
		// 1. Origin / Referer Validation (Anti-CSRF)
		const origin = request.headers.get("origin") || request.headers.get("referer");
		const host = request.headers.get("host") || new URL(request.url).host;
		if (origin) {
			try {
				const originHost = new URL(origin).host;
				if (originHost !== host) {
					return new Response(JSON.stringify({ error: "Akses ditolak: Invalid Origin." }), {
						status: 403,
						headers: { "Content-Type": "application/json" },
					});
				}
			} catch {
				return new Response(JSON.stringify({ error: "Akses ditolak: Malformed Origin." }), {
					status: 403,
					headers: { "Content-Type": "application/json" },
				});
			}
		}

		// 2. Batas Ukuran Payload (Anti-DoS Memory Exhaustion)
		const contentLength = Number(request.headers.get("content-length") || "0");
		if (contentLength > 16 * 1024) {
			return new Response(
				JSON.stringify({ error: "Ukuran data terlalu besar (maksimal 16KB)." }),
				{ status: 413, headers: { "Content-Type": "application/json" } },
			);
		}

		const db = await getDb();
		if (!db) {
			return new Response(
				JSON.stringify({ error: "D1 Database binding tidak ditemukan." }),
				{ status: 500, headers: { "Content-Type": "application/json" } },
			);
		}

		const body = await request.json().catch(() => null);
		if (!body || typeof body !== "object") {
			return new Response(JSON.stringify({ error: "Format data request tidak valid." }), {
				status: 400,
				headers: { "Content-Type": "application/json" },
			});
		}

		// 3. Anti-Bot Honeypot (Silent Drop jika bot mengisi field jebakan)
		if (body.website || body.company || body.company_name) {
			return new Response(
				JSON.stringify({ success: true, message: "RSVP dan doa berhasil dikirim." }),
				{ status: 200, headers: { "Content-Type": "application/json" } },
			);
		}

		// 4. Client IP & Server-Side Atomic Rate Limiting (Maks 5 submit per 10 menit)
		const ip = getClientIp(request, clientAddress);
		const ipHashed = await hashIp(ip);
		const allowed = await checkRateLimit(db, ipHashed, 5, 600);
		if (!allowed) {
			return new Response(
				JSON.stringify({ error: "Terlalu banyak pengiriman. Silakan tunggu 10 menit." }),
				{ status: 429, headers: { "Content-Type": "application/json" } },
			);
		}

		// 5. Cloudflare Turnstile Verification (Anti-Spam CAPTCHA)
		const turnstileSecret = getTurnstileSecret();
		const turnstileToken = body["cf-turnstile-response"] || body.turnstileToken;

		if (turnstileSecret) {
			const turnstileResult = await verifyTurnstileToken(turnstileToken, turnstileSecret, ip);
			if (!turnstileResult.success) {
				return new Response(
					JSON.stringify({ error: "Verifikasi anti-spam gagal. Silakan muat ulang halaman." }),
					{ status: 400, headers: { "Content-Type": "application/json" } },
				);
			}
		}

		// 6. Validasi & Sanitasi Input
		const attendance =
			body.attendance === "Tidak hadir"
				? "Tidak hadir"
				: body.attendance === "Hadir"
				? "Hadir"
				: null;

		if (!attendance) {
			return new Response(
				JSON.stringify({ error: "Pilihan kehadiran wajib 'Hadir' atau 'Tidak hadir'." }),
				{ status: 400, headers: { "Content-Type": "application/json" } },
			);
		}

		const message = sanitizeText(typeof body.message === "string" ? body.message : "", 500);
		const slug = typeof body.slug === "string" ? body.slug.trim() : "";

		// 7. Anti-IDOR & Whitelist Tamu: Hanya tamu dengan slug sah yang terdaftar di D1 yang boleh RSVP
		if (!slug) {
			return new Response(
				JSON.stringify({ error: "Akses ditolak: Tautan undangan khusus diperlukan untuk mengisi RSVP." }),
				{ status: 403, headers: { "Content-Type": "application/json" } },
			);
		}

		const existing = await db
			.prepare("SELECT id, name FROM guests WHERE slug = ?")
			.bind(slug)
			.first<{ id: number; name: string }>();

		if (!existing) {
			return new Response(
				JSON.stringify({ error: "Akses ditolak: Tamu tidak terdaftar dalam daftar undangan resmi." }),
				{ status: 403, headers: { "Content-Type": "application/json" } },
			);
		}

		// Simpan status kehadiran & ucapan ke D1
		await db
			.prepare("UPDATE guests SET status_rsvp = ?, wishes = ? WHERE id = ?")
			.bind(attendance, message, existing.id)
			.run();

		return new Response(
			JSON.stringify({
				success: true,
				message: "RSVP dan doa berhasil dikirim.",
				guestName: existing.name,
				attendance,
				wishes: message,
			}),
			{ status: 200, headers: { "Content-Type": "application/json" } },
		);
	} catch (error: unknown) {
		const message = error instanceof Error ? error.message : "Gagal menyimpan RSVP.";
		return new Response(JSON.stringify({ error: message }), {
			status: 500,
			headers: { "Content-Type": "application/json" },
		});
	}
};
