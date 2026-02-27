// Parameterized SQL
db.query("SELECT * FROM users WHERE id=$1", [req.query.id])
db.execute("SELECT * FROM users WHERE id=?", [params.id])
knex.raw("SELECT * FROM users WHERE id=?", [id])

// Safe constant query
db.query("SELECT * FROM users")
db.execute('SELECT 1')

// Safe MongoDB
db.collection('users').find({ id: req.params.id })
db.collection('products').find({ category: "electronics" })
