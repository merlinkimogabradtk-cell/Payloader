
import fs from 'fs';
import path from 'path';

// Read files
const navPath = path.join(process.cwd(), 'src/data/navigation.ts');
const webPath = path.join(process.cwd(), 'src/data/webPayloads.ts');
const intranetPath = path.join(process.cwd(), 'src/data/intranetPayloads.ts');
const toolsPath = path.join(process.cwd(), 'src/data/toolCommands.ts');

const navContent = fs.readFileSync(navPath, 'utf8');
const webContent = fs.readFileSync(webPath, 'utf8');
const intranetContent = fs.readFileSync(intranetPath, 'utf8');
const toolsContent = fs.readFileSync(toolsPath, 'utf8');

// Extract IDs
const payloadIds = [];
const toolIds = [];

const payloadIdRegex = /payloadId:\s*'([^']+)'/g;
const toolIdRegex = /toolId:\s*'([^']+)'/g;

let match;
while ((match = payloadIdRegex.exec(navContent)) !== null) {
    payloadIds.push(match[1]);
}
while ((match = toolIdRegex.exec(navContent)) !== null) {
    toolIds.push(match[1]);
}

// Extract existing IDs
const existingPayloadIds = new Set();
const existingToolIds = new Set();

const idRegex = /id:\s*'([^']+)'/g;

while ((match = idRegex.exec(webContent)) !== null) {
    existingPayloadIds.add(match[1]);
}
while ((match = idRegex.exec(intranetContent)) !== null) {
    existingPayloadIds.add(match[1]);
}
while ((match = idRegex.exec(toolsContent)) !== null) {
    existingToolIds.add(match[1]);
}

// Find missing
const missingPayloads = payloadIds.filter(id => !existingPayloadIds.has(id));
const missingTools = toolIds.filter(id => !existingToolIds.has(id));

console.log('Missing Payloads:', missingPayloads);
console.log('Missing Tools:', missingTools);
