You are working directly on D:\Mini.

Your mission is to make ARGUS work in production on Vercel.

Known production error:

ERR_REQUIRE_ESM:
require() of ES Module /var/task/artifacts/api-server/src/app.js
from /var/task/index.js not supported.

The same error occurs from /var/task/api/index.js.

Do NOT guess.

First inspect the repository and the locally generated Vercel output:

.vercel/output/config.json
.vercel/output/functions/

Run:

vercel build

Then inspect the generated functions and determine why Vercel's Express preset is generating CommonJS wrappers that require the ESM app.

Fix the architecture using a Vercel-supported approach.

Do not make random changes.

After every fix:

1. Run typecheck.
2. Run the API build.
3. Run vercel build.
4. Inspect the generated output.
5. Deploy with vercel --prod.
6. Test the real production URL using vercel curl.
7. Read production logs.
8. If it fails, diagnose the actual error and try another valid approach.
9. Continue until /api/healthz works.
10. Then inspect and test the project's other API routes and frontend.

Never declare success just because Vercel says Ready.

Never stop after one failed approach.

Do not expose secrets from .env.local.

Do not commit logs or unrelated files.

Do not stage:
artifacts/security-engine/engine-e2e.err.log

At the end, report the root cause, files changed, tests performed, production URL, and final status.
