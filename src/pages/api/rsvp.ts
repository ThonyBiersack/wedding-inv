import type { APIRoute } from "astro";
import { env } from "cloudflare:workers";
import { getDb } from "../../lib/db";
import { sanitizeText, hashIp, verifyTurnstileToken, checkRateLimit } from "../../lib/security";

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

		// 2. Anti-Bot Honeypot (Silent Drop jika bot mengisi field jebakan)
		if (body.website || body.company || body.company_name) {
			return new Response(
				JSON.stringify({ success: true, message: "RSVP dan doa berhasil dikirim." }),
				{ status: 200, headers: { "Content-Type": "application/json" } },
			);
		}

		// 3. Client IP & Server-Side Rate Limiting (Maks 5 submit per 10 menit)
		const ip =
			request.headers.get("cf-connecting-ip") ||
			request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
			clientAddress ||
			"127.0.0.1";
		const ipHashed = await hashIp(ip);
		const allowed = await checkRateLimit(db, ipHashed, 5, 600);
		if (!allowed) {
			return new Response(
				JSON.stringify({ error: "Terlalu banyak pengiriman. Silakan tunggu 10 menit." }),
				{ status: 429, headers: { "Content-Type": "application/json" } },
			);
		}

		// 4. Cloudflare Turnstile Verification (Anti-Spam CAPTCHA)
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

		// 5. Validasi & Sanitasi Input Ketat
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
		const rawName =
			typeof body.name === "string"
				? body.name
				: typeof body.guestName === "string"
				? body.guestName
				: "";
		const sanitizedName = sanitizeText(rawName, 80);
		const slug = typeof body.slug === "string" ? body.slug.trim() : "";

		let guestDisplayName = sanitizedName;

		if (slug) {
			// Validasi tamu terdaftar di database D1
			const existing = await db
				.prepare("SELECT id, name FROM guests WHERE slug = ?")
				.bind(slug)
				.first<{ id: number; name: string }>();

			if (existing) {
				guestDisplayName = existing.name;
				await db
					.prepare("UPDATE guests SET status_rsvp = ?, wishes = ? WHERE id = ?")
					.bind(attendance, message, existing.id)
					.run();
			} else if (sanitizedName) {
				await db
					.prepare("INSERT INTO guests (name, slug, status_rsvp, wishes) VALUES (?, ?, ?, ?)")
					.bind(sanitizedName, slug, attendance, message)
					.run();
			} else {
				return new Response(
					JSON.stringify({ error: "Akses ditolak: Tamu tidak terdaftar dalam daftar undangan resmi." }),
					{ status: 403, headers: { "Content-Type": "application/json" } },
				);
			}
		} else {
			if (!sanitizedName) {
				return new Response(
					JSON.stringify({ error: "Nama tamu wajib diisi (maksimal 80 karakter)." }),
					{ status: 400, headers: { "Content-Type": "application/json" } },
				);
			}
			const genSlug = `${sanitizedName.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-${Date.now().toString(36)}`;
			await db
				.prepare("INSERT INTO guests (name, slug, status_rsvp, wishes) VALUES (?, ?, ?, ?)")
				.bind(sanitizedName, genSlug, attendance, message)
				.run();
		}

		return new Response(
			JSON.stringify({
				success: true,
				message: "RSVP dan doa berhasil dikirim.",
				guestName: guestDisplayName,
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
