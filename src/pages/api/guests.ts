import type { APIRoute } from "astro";
import { env } from "cloudflare:workers";
import { getDb } from "../../lib/db";
import { sanitizeText } from "../../lib/security";

export const prerender = false;

function getAdminSecret(): string | undefined {
	try {
		if (typeof env !== "undefined" && (env as any)?.ADMIN_SECRET_KEY) {
			return (env as any).ADMIN_SECRET_KEY;
		}
	} catch {}
	return (import.meta as any).env?.ADMIN_SECRET_KEY;
}


function isAuthorized(request: Request): boolean {
	const adminSecret = getAdminSecret();
	if (!adminSecret) return true;

	const authHeader = request.headers.get("authorization");
	const xKey = request.headers.get("x-admin-key");
	const urlKey = new URL(request.url).searchParams.get("key");

	const token =
		(authHeader?.startsWith("Bearer ") ? authHeader.slice(7).trim() : null) ||
		xKey?.trim() ||
		urlKey?.trim();

	return Boolean(token && token === adminSecret);
}

function slugify(text: string): string {
	return text
		.toString()
		.toLowerCase()
		.trim()
		.replace(/\s+/g, "-")
		.replace(/[^\w\-]+/g, "")
		.replace(/\-\-+/g, "-");
}

export const GET: APIRoute = async ({ request }) => {
	try {
		if (!isAuthorized(request)) {
			return new Response(
				JSON.stringify({ error: "Akses ditolak: Passcode Admin tidak valid." }),
				{ status: 401, headers: { "Content-Type": "application/json" } },
			);
		}

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
		if (!isAuthorized(request)) {
			return new Response(
				JSON.stringify({ error: "Akses ditolak: Passcode Admin tidak valid." }),
				{ status: 401, headers: { "Content-Type": "application/json" } },
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

		let baseSlug = slugify(name);
		if (!baseSlug) {
			baseSlug = "tamu";
		}

		const existing = await db
			.prepare("SELECT id FROM guests WHERE slug = ?")
			.bind(baseSlug)
			.first();

		const finalSlug = existing
			? `${baseSlug}-${Math.random().toString(36).slice(2, 6)}`
			: baseSlug;

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
		if (!isAuthorized(request)) {
			return new Response(
				JSON.stringify({ error: "Akses ditolak: Passcode Admin tidak valid." }),
				{ status: 401, headers: { "Content-Type": "application/json" } },
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

		if (!id || Number.isNaN(id)) {
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
