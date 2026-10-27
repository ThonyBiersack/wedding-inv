import type { D1Database } from "@cloudflare/workers-types";
import { env } from "cloudflare:workers";

export async function getDb(): Promise<D1Database | null> {
	if (env && (env as any).DB) {
		return (env as any).DB as D1Database;
	}
	return null;
}
