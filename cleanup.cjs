const fs = require('fs');
const path = require('path');

const dir = 'C:\\Users\\Hezihao\\Desktop\\3';
const keep = new Set(['cyber-arsenal-merged', 'caihong']);

const entries = fs.readdirSync(dir);
let deleted = 0;

for (const entry of entries) {
  const full = path.join(dir, entry);
  const stat = fs.statSync(full);
  
  if (stat.isDirectory()) {
    if (!keep.has(entry)) {
      fs.rmSync(full, { recursive: true, force: true });
      console.log('DIR  deleted:', entry);
      deleted++;
    }
  } else {
    // Delete all files except nothing - we want ONLY the project folder
    fs.unlinkSync(full);
    console.log('FILE deleted:', entry);
    deleted++;
  }
}

console.log(`\nTotal deleted: ${deleted}`);
console.log('Remaining:', fs.readdirSync(dir).join(', '));
