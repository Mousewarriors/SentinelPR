// In comments
// db.query(`SELECT * FROM users WHERE id=${id}`)
/* db.execute("SELECT * FROM " + table) */

// String creation without execution
const sql = `SELECT * FROM users WHERE id=${id}`;
const filter = { [someVar]: "value" };

// Safe tagged templates (non-db context)
const label = i18n`Hello ${name}`;

// Non-concatenation plus
const count = 1 + 2;
const name = "Hello" + " World";
