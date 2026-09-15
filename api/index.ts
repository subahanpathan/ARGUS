let appPromise: Promise<any>;

function getApp() {
  if (!appPromise) {
    // @ts-ignore - bundled ESM module has no type declarations
    appPromise = import("../artifacts/api-server/dist/vercel.mjs");
  }
  return appPromise;
}

export default async function handler(req: any, res: any) {
  const { default: app } = await getApp();
  return app(req, res);
}
