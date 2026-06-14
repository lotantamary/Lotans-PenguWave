import { openDb } from "./db";
import { seed } from "./seed";
import { buildApp } from "./app";

const db = openDb();
seed(db);

const port = Number(process.env.PORT ?? 3001);
const app = buildApp(db);

app.listen(port, () => {
  console.log(`PenguWave backend listening on http://localhost:${port}`);
});
