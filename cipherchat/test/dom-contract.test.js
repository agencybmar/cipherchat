'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

test('every DOM id requested by app.js exists in index.html', () => {
  const root = path.join(__dirname, '..');
  const html = fs.readFileSync(path.join(root, 'public', 'index.html'), 'utf8');
  const app = fs.readFileSync(path.join(root, 'public', 'app.js'), 'utf8');
  const htmlIds = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]));
  const requestedIds = [...app.matchAll(/getElementById\('([^']+)'\)/g)].map((match) => match[1]);
  const missing = requestedIds.filter((id) => !htmlIds.has(id));
  assert.deepEqual(missing, []);
});
