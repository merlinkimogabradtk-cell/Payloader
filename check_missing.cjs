
const fs = require('fs');
const path = require('path');

const navPath = path.join(__dirname, 'src', 'data', 'navigation.ts');
const webPath = path.join(__dirname, 'src', 'data', 'webPayloads.ts');
const intraPath = path.join(__dirname, 'src', 'data', 'intranetPayloads.ts');

const navContent = fs.readFileSync(navPath, 'utf8');
const webContent = fs.readFileSync(webPath, 'utf8');
const intraContent = fs.readFileSync(intraPath, 'utf8');

const payloadIdRegex = /payloadId:\s*'([^']+)'/g;
const missing = [];
let match;

while ((match = payloadIdRegex.exec(navContent)) !== null) {
  const id = match[1];
  const webRegex = new RegExp(`id:\\s*'${id}'`);
  const intraRegex = new RegExp(`id:\\s*'${id}'`);
  
  if (!webRegex.test(webContent) && !intraRegex.test(intraContent)) {
    missing.push(id);
  }
}

console.log('Missing Payload IDs:', missing);
console.log('Total Missing:', missing.length);
