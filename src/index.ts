import { ExecutionContext } from '@cloudflare/workers-types/2023-07-01/index';

export default {
	async fetch(request, env, ctx: ExecutionContext): Promise<Response> {
		const NONCE_REGEX = (env.NONCE_REGEX && new RegExp(env.NONCE_REGEX)) || /{{NONCE}}/g;
		const response = await fetch(request);

		if (!response.headers.get('Content-Type')?.startsWith('text/')) {
			return response;
		}

		const body = await response.clone().text();

		if (!body.match(NONCE_REGEX)) {
			return response;
		}

		const nonce = Date.now().toString(36) + Math.random().toString(36).substring(2);

		const cspEndpoint = env.CSP_ENDPOINT;
		const srcConnect = env.CONNECT_SRC;
		const srcScript = env.SCRIPT_SRC;

		const headers = new Headers(response.headers);

		if (cspEndpoint) {
			headers.set('Reporting-Endpoints', `csp-endpoint="${cspEndpoint}"`);
			headers.set('Content-Security-Policy-Report-Only', `default-src 'self'; script-src 'self' ${srcScript} 'unsafe-inline' 'nonce-${nonce}' 'strict-dynamic' http: https:; object-src 'none'; base-uri 'none'; connect-src 'self' ${srcConnect}; style-src 'self' 'unsafe-inline' 'nonce-${nonce}'; require-trusted-types-for 'script'; report-to csp-endpoint; report-uri ${cspEndpoint}`);
		} else {
			headers.set('Content-Security-Policy', `default-src 'self'; script-src 'self' ${srcScript} 'unsafe-inline' 'nonce-${nonce}' 'strict-dynamic' http: https:; object-src 'none'; base-uri 'none'; connect-src 'self' ${srcConnect}; style-src 'self' 'unsafe-inline' 'nonce-${nonce}'; require-trusted-types-for 'script'`);
		}

		return new Response(
			body.replace(NONCE_REGEX, nonce),
			{
				headers: headers,
				status: response.status,
				statusText: response.statusText
			}
		);
	}
} satisfies ExportedHandler<Env>;
