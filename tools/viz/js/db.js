/* eTrace-Diag viz — sql.js init + session discovery + query primitives. */
(function (global) {
  'use strict';
  const V = global.V = global.V || {};

  V.db = {
    sqlJs: null,

    async init() {
      if (V.db.sqlJs) return V.db.sqlJs;
      V.db.sqlJs = await initSqlJs({ locateFile: (f) => 'vendor/' + f });
      return V.db.sqlJs;
    },

    // open a session's etrace.sqlite3 File handle -> in-memory sql.js Database
    async open(file) {
      const SQL = await V.db.init();
      const buf = new Uint8Array(await file.arrayBuffer());
      return new SQL.Database(buf);
    },

    // small-table helper: return [{col: val}, ...] for the first result set
    query(db, sql, params) {
      const st = db.prepare(sql);
      if (params) st.bind(params);
      const out = [];
      while (st.step()) {
        const row = st.getAsObject();
        out.push(row);
      }
      st.free();
      return out;
    },

    // large-table streaming: cb(rowObj) per row; never materializes an array
    step(db, sql, params, cb) {
      const st = db.prepare(sql);
      if (params) st.bind(params);
      let n = 0;
      while (st.step()) {
        cb(st.getAsObject());
        n++;
      }
      st.free();
      return n;
    },

    // single scalar (first row, first column)
    scalar(db, sql, params) {
      const st = db.prepare(sql);
      if (params) st.bind(params);
      let v = null;
      if (st.step()) v = st.get()[0];
      st.free();
      return v;
    },
  };
})(typeof window !== 'undefined' ? window : globalThis);
