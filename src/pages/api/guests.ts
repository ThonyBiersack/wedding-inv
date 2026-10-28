import type { APIRoute } from "astro";
import { env } from "cloudflare:workers";
import { getDb } from "../../lib/db";
import {
	sanitizeText,
	timingSafeEqual,
	generateSecureSlug,
	getClientIp,
	hashIp,
	checkRateLimit,
} from "../../lib/security";

export const prerender = false;

function getAdminSecret(): string | null {
	try {
		if (typeof env !== "undefined" && (env as any)?.ADMIN_SECRET_KEY) {
			return (env as any).ADMIN_SECRET_KEY;
		}
	} catch {}
	return (import.meta as any).env?.ADMIN_SECRET_KEY || null;
}

function isAuthorized(request: Request): boolean {
	const adminSecret = getAdminSecret();
	// FAIL-CLOSED: Jika admin secret belum disetel di server, akses wajib ditolak
	if (!adminSecret) return false;

	const authHeader = request.headers.get("authorization");
	const xKey = request.headers.get("x-admin-key");

	const token =
		(authHeader?.startsWith("Bearer ") ? authHeader.slice(7).trim() : null) ||
		xKey?.trim();

	if (!token) return false;

	return timingSafeEqual(token, adminSecret);
}

async function verifyAuthWithRateLimit(request: Request): Promise<Response | null> {
	if (isAuthorized(request)) {
		return null;
	}

	// Brute-force throttling: Batasi maksimal 10 kegagalan autentikasi per 15 menit per IP
	const db = await getDb();
	if (db) {
		const ip = getClientIp(request);
		const ipHash = await hashIp(ip + ":admin_api");
		const allowed = await checkRateLimit(db, ipHash, 10, 900);
		if (!allowed) {
			return new Response(
				JSON.stringify({ error: "Terlalu banyak percobaan autentikasi gagal. Silakan tunggu 15 menit." }),
				{ status: 429, headers: { "Content-Type": "application/json" } },
			);
		}
	}

	return new Response(
		JSON.stringify({ error: "Akses ditolak: Autentikasi Admin diperlukan." }),
		{ status: 401, headers: { "Content-Type": "application/json" } },
	);
}

export const GET: APIRoute = async ({ request }) => {
	try {
		const authError = await verifyAuthWithRateLimit(request);
		if (authError) return authError;

		const db = await getDb();
		if (!db) {
			return new Response(
				JSON.stringify({ error: "D1 Database binding tidak ditemukan." }),
				{ status: 500, headers: { "Content-Type": "application/json" } },
			);
		}

		const { results } = await db
			.prepare("SELECT * FROM guests ORDER BY id DESC")
			.all();

		return new Response(JSON.stringify(results ?? []), {
			status: 200,
			headers: { "Content-Type": "application/json" },
		});
	} catch (error: unknown) {
		const message = error instanceof Error ? error.message : "Terjadi kesalahan server";
		return new Response(JSON.stringify({ error: message }), {
			status: 500,
			headers: { "Content-Type": "application/json" },
		});
	}
};

export const POST: APIRoute = async ({ request }) => {
	try {
		const authError = await verifyAuthWithRateLimit(request);
		if (authError) return authError;

		// Batas Ukuran Payload (Anti-DoS Memory Exhaustion)
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
		const rawName = typeof body?.name === "string" ? body.name : "";
		const name = sanitizeText(rawName, 80);

		if (!name) {
			return new Response(
				JSON.stringify({ error: "Nama tamu tidak boleh kosong (maksimal 80 karakter)." }),
				{ status: 400, headers: { "Content-Type": "application/json" } },
			);
		}

		// Buat slug unguessable & cek collision
		let finalSlug = generateSecureSlug(name);
		let attempts = 0;
		while (attempts < 5) {
			const existing = await db
				.prepare("SELECT id FROM guests WHERE slug = ?")
				.bind(finalSlug)
				.first();
			if (!existing) break;
			finalSlug = generateSecureSlug(name);
			attempts++;
		}

		const insertResult = await db
			.prepare("INSERT INTO guests (name, slug) VALUES (?, ?) RETURNING *")
			.bind(name, finalSlug)
			.first();

		return new Response(
			JSON.stringify({ success: true, guest: insertResult }),
			{ status: 201, headers: { "Content-Type": "application/json" } },
		);
	} catch (error: unknown) {
		const message = error instanceof Error ? error.message : "Gagal menyimpan tamu.";
		return new Response(JSON.stringify({ error: message }), {
			status: 500,
			headers: { "Content-Type": "application/json" },
		});
	}
};

export const DELETE: APIRoute = async ({ request }) => {
	try {
		const authError = await verifyAuthWithRateLimit(request);
		if (authError) return authError;

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
		const id = Number(body?.id);

		if (!id || !Number.isInteger(id) || id <= 0) {
			return new Response(
				JSON.stringify({ error: "ID tamu tidak valid." }),
				{ status: 400, headers: { "Content-Type": "application/json" } },
			);
		}

		await db.prepare("DELETE FROM guests WHERE id = ?").bind(id).run();

		return new Response(
			JSON.stringify({ success: true, message: "Tamu berhasil dihapus." }),
			{ status: 200, headers: { "Content-Type": "application/json" } },
		);
	} catch (error: unknown) {
		const message = error instanceof Error ? error.message : "Gagal menghapus data tamu.";
		return new Response(JSON.stringify({ error: message }), {
			status: 500,
			headers: { "Content-Type": "application/json" },
		});
	}
};
