require("dotenv").config();
const { createApp } = require("./src/app");
const { initDb } = require("./src/db");
const port = Number(process.env.PORT || 4000);
initDb();
const app = createApp();
app.listen(port, () => console.log(`File Storage App running at http://localhost:${port}`));
