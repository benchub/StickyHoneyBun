#!/usr/bin/env node
//
// ORM tester: Sequelize (popular JavaScript ORM, used in Node web apps).
//
// findAll is Sequelize's idiomatic "fetch all rows" call; under the
// hood it issues `SELECT id, honey FROM honey_table ORDER BY id ASC`
// via the `pg` npm package and materializes each row through the
// text protocol. Typeoutput fires for the honey column.
//
// Connects via libpq env vars. The pg package respects PGHOST as a
// Unix-socket directory path the same way libpq does, so the test
// driver's env is sufficient.

const { Sequelize, DataTypes } = require('sequelize');

const seq = new Sequelize(
  process.env.PGDATABASE,
  process.env.PGUSER,
  process.env.PGPASSWORD || null,
  {
    host:    process.env.PGHOST,
    port:    parseInt(process.env.PGPORT, 10),
    dialect: 'postgres',
    logging: false,
  },
);

const HoneyTable = seq.define('HoneyTable', {
  id:    { type: DataTypes.INTEGER, primaryKey: true },
  honey: DataTypes.TEXT,
}, {
  tableName:  'honey_table',
  timestamps: false,
});

(async () => {
  try {
    const rows = await HoneyTable.findAll({ order: [['id', 'ASC']] });
    const firstHoney = rows.length > 0 ? JSON.stringify(rows[0].honey) : 'none';
    process.stderr.write(
      `sequelize: fetched ${rows.length} row(s); first honey value = ${firstHoney}\n`
    );
    await seq.close();
    process.exit(0);
  } catch (err) {
    process.stderr.write(`sequelize: ERROR ${err.message}\n`);
    process.exit(1);
  }
})();
