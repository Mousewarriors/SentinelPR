// SQL001
db.query(`SELECT * FROM users WHERE id=${req.query.id}`)
db.execute(`UPDATE products SET price=${newPrice}`)
prisma.$queryRaw`SELECT * FROM users WHERE email=${email}`
knex.raw(`SELECT * FROM orders WHERE status=${status}`)
sequelize.query(`SELECT * FROM logs WHERE type=${type}`)

// SQL002
db.query("SELECT * FROM users WHERE id=" + req.query.id)
db.execute('SELECT * FROM orders WHERE status=' + status)
knex.raw("SELECT * FROM logs WHERE level=" + level)
prisma.$queryRawUnsafe("SELECT * FROM users WHERE id=" + id)

// SQL003
prisma.$queryRawUnsafe(userQuery)
$queryRawUnsafe("SELECT 1")
entityManager.query(`SELECT * FROM users WHERE name='${name}'`)

// SQL004
db.query(`SELECT * FROM users WHERE id=${req.query.id}`)
db.execute("SELECT * FROM users WHERE id=" + req.params.id)

// NOSQL001
db.collection('users').find({ "$where": `this.name == "${req.query.name}"` })
db.collection('products').find({ "price": { "$regex": req.body.pattern } })
db.collection('logs').find({ "$expr": req.query.expr })

// NOSQL002
Users.findOne({ [req.query.field]: "value" })
Models.find({ [req.body.key]: req.body.val })

// NOSQL003
collection.find(JSON.parse(req.body.query))
