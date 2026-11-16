// OAuth 2.0 authorization server for the token-based baselines, built on
// panva/oidc-provider (an OpenID Certified implementation) instead of
// hand-written token logic. One process per baseline mode:
//
//   bearer     client_credentials, JWT access token, no binding
//   certbound  + RFC 8705 certificate-bound tokens (cnf.x5t#S256)
//   dpop       + RFC 9449 DPoP-bound tokens (cnf.jkt), client sends a DPoP proof
//   dpop_rar   + RFC 9396 authorization_details of type "agent_task", granted
//              only within the client's role ceiling (same roles.json the
//              ZT-COMM Policy Store uses), optionally extended by a
//              user-signed delegation grant
//
// Clients authenticate with mutual TLS (RFC 8705 tls_client_auth): the
// client_id is the certificate CN.
//
// Usage: node server.mjs <mode> <port>

import fs from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Provider, { errors } from 'oidc-provider';
import * as jose from 'jose';

const here = path.dirname(fileURLToPath(import.meta.url));
const certs = path.join(here, '..', 'certs');
const mode = process.argv[2];
const port = Number(process.argv[3]);
const issuer = `https://localhost:${port}`;
const RESOURCE = 'agent://agent_b';

const { roles, identity_roles: identityRoles } = JSON.parse(fs.readFileSync(path.join(certs, 'roles.json')));
const userIdpKey = await jose.importJWK(JSON.parse(fs.readFileSync(path.join(certs, 'user_idp_pub.jwk'))), 'ES256');

function roleFor(identity) {
  if (identityRoles[identity]) return identityRoles[identity];
  const prefix = identity.split('-')[0];
  return roles[`${prefix}-reader`] && identity !== prefix ? `${prefix}-reader` : null;
}

const covered = (pairs, entries) => pairs.every(([op, dt]) => entries.some(([ops, dts]) => ops.includes(op) && dts.includes(dt)));

async function policy(identity, detail) {
  const role = roleFor(identity);
  if (!role) throw new errors.InvalidAuthorizationDetails(`identity ${identity} has no role`);
  const entries = [...roles[role].entries];
  if (detail.user_grant) {
    let claims;
    try {
      ({ payload: claims } = await jose.jwtVerify(detail.user_grant, userIdpKey, { issuer: 'user-idp' }));
    } catch (e) {
      throw new errors.InvalidAuthorizationDetails(`user grant invalid: ${e.code || e.name}`);
    }
    if (claims.act?.sub !== identity) throw new errors.InvalidAuthorizationDetails('user grant delegated to a different agent');
    entries.push([claims.operations, claims.data_types]);
  }
  const pairs = detail.actions.flatMap((op) => detail.datatypes.map((dt) => [op, dt]));
  if (!covered(pairs, entries)) throw new errors.InvalidAuthorizationDetails(`requested scope exceeds role ${role}`);
  return { type: 'agent_task', actions: [...detail.actions].sort(), datatypes: [...detail.datatypes].sort() };
}

// Register every identity that has a certificate as a client.
const clients = fs.readdirSync(certs)
  .filter((f) => f.endsWith('_cert.pem') && !['ca_cert.pem', 'agent_b_cert.pem', 'authz_server_cert.pem'].includes(f))
  .map((f) => f.replace('_cert.pem', ''))
  .map((cn) => ({
    client_id: cn,
    token_endpoint_auth_method: 'tls_client_auth',
    id_token_signed_response_alg: 'ES256',
    tls_client_auth_subject_dn: `CN=${cn}`,
    grant_types: ['client_credentials'],
    response_types: [],
    redirect_uris: [],
    tls_client_certificate_bound_access_tokens: mode === 'certbound',
    dpop_bound_access_tokens: mode.startsWith('dpop'),
    ...(mode === 'dpop_rar' ? { authorization_details_types: ['agent_task'] } : {}),
  }));

const signingKey = await jose.generateKeyPair('ES256', { extractable: true });
const jwk = { ...(await jose.exportJWK(signingKey.privateKey)), alg: 'ES256', use: 'sig', kid: 'as-1' };

const provider = new Provider(issuer, {
  clients,
  jwks: { keys: [jwk] },
  clientAuthMethods: ['tls_client_auth'],
  features: {
    devInteractions: { enabled: false },
    clientCredentials: { enabled: true },
    introspection: { enabled: false },
    dPoP: { enabled: true, requireNonce: () => false },
    mTLS: {
      enabled: true,
      tlsClientAuth: true,
      certificateBoundAccessTokens: true,
      // Node already verified the chain against our CA during the TLS handshake.
      certificateAuthorized: (ctx) => ctx.req.socket.authorized === true,
      certificateSubjectMatches(ctx, property, expected) {
        if (property !== 'tls_client_auth_subject_dn') return false;
        const subject = ctx.req.socket.getPeerCertificate(false)?.subject;
        return subject && `CN=${subject.CN}` === expected;
      },
      getCertificate(ctx) {
        const peer = ctx.req.socket.getPeerCertificate(false);
        if (!peer || !peer.raw) return undefined;
        return `-----BEGIN CERTIFICATE-----\n${peer.raw.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;
      },
    },
    resourceIndicators: {
      enabled: true,
      defaultResource: () => RESOURCE,
      useGrantedResource: () => true,
      getResourceServerInfo: () => ({
        scope: '',
        audience: RESOURCE,
        accessTokenTTL: 300,
        accessTokenFormat: 'jwt',
        jwt: { sign: { alg: 'ES256' } },
      }),
    },
    richAuthorizationRequests: {
      enabled: mode === 'dpop_rar',
      types: {
        agent_task: {
          validate(ctx, detail) {
            const ok = Array.isArray(detail.actions) && detail.actions.length
              && Array.isArray(detail.datatypes) && detail.datatypes.length;
            if (!ok) throw new errors.InvalidAuthorizationDetails('agent_task needs actions and datatypes');
          },
        },
      },
      authorizationDetailsForAccessToken: async (ctx, token) => {
        const requested = JSON.parse(ctx.oidc.params.authorization_details || '[]');
        return Promise.all(requested.map((d) => policy(ctx.oidc.client.clientId, d)));
      },
      authorizationDetailsForGrantSource: () => undefined,
      authorizationDetailsForIntrospection: (ctx, token) => token.rar,
    },
  },
  ttl: { ClientCredentials: 300 },
});
provider.proxy = false;
provider.on('server_error', (ctx, err) => console.error('[authz] server_error', err));

provider.use(async (ctx, next) => {
  if (ctx.path === '/token' && ctx.method === 'POST') ctx.req.socket.setNoDelay(true);
  await next();
});

const server = https.createServer({
  key: fs.readFileSync(path.join(certs, 'authz_server_key.pem')),
  cert: fs.readFileSync(path.join(certs, 'authz_server_cert.pem')),
  ca: fs.readFileSync(path.join(certs, 'ca_cert.pem')),
  requestCert: true,
  rejectUnauthorized: true,
  minVersion: 'TLSv1.3',
}, provider.callback());
server.on('connection', (s) => s.setNoDelay(true));
server.keepAliveTimeout = 30000;
fs.writeFileSync(path.join(certs, `as_${mode}_jwks.json`), JSON.stringify(await jose.exportJWK(signingKey.publicKey)));
server.listen(port, 'localhost', () => console.log(`[authz:${mode}] ${issuer} with ${clients.length} clients`));
