/// <reference path="../.astro/types.d.ts" />

type D1Database = import("@cloudflare/workers-types").D1Database;

type ENV = {
	DB: D1Database;
	DB_NAME?: string;
	DB_ID?: string;
	TURNSTILE_SECRET_KEY?: string;
	ADMIN_SECRET_KEY?: string;
};


type Runtime = import("@astrojs/cloudflare").Runtime<ENV>;

declare namespace App {
	interface Locals extends Runtime {}
}
