import { runUserQuery } from "./cross_sink.js";

export async function handleSearch(req, res, pool) {
  const rawName = req.query.name;
  const rows = await runUserQuery(pool, rawName);
  res.json(rows);
}

export async function createOrder(req, orders) {
  return orders.create({ itemId: req.body.itemId, price: req.body.price });
}

export function decodeSession(token) {
  return jwt.decode(token);
}

export function registerAdminRoutes(app) {
  app.delete("/api/admin/users/:id", async (req, res) => res.json({ deleted: req.params.id }));
}
