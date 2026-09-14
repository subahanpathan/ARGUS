let appPromise;

module.exports = async (req, res) => {
  if (!appPromise) {
    appPromise = import("./artifacts/api-server/dist/vercel.mjs");
  }

  const { default: app } = await appPromise;
  return app(req, res);
};
