
const fs = require('fs');

const webPayloadsFile = 'src/data/webPayloads.ts';
const intranetPayloadsFile = 'src/data/intranetPayloads.ts';

function checkFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  // We need to parse the array of objects.
  // Since it's TS/JS, we can't easily JSON.parse.
  // We'll use a simple state machine or regex to find empty execution arrays.
  
  // Look for id: '...' followed eventually by execution: []
  // This is tricky with regex.
  // Instead, let's look for "execution: \[\s*\]" and find the preceding ID.
  
  const lines = content.split('\n');
  let currentId = null;
  const emptyExecutionIds = [];
  const missingSyntaxIds = [];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const idMatch = line.match(/id:\s*'([^']+)'/);
    if (idMatch) {
      currentId = idMatch[1];
    }
    
    if (line.includes('execution: []') || line.includes('execution: [ ]')) {
      if (currentId) {
        emptyExecutionIds.push(currentId);
      }
    }
  }
  
  return { emptyExecutionIds };
}

const webResult = checkFile(webPayloadsFile);
const intranetResult = checkFile(intranetPayloadsFile);

console.log('Web Payloads with empty execution:', webResult.emptyExecutionIds);
console.log('Intranet Payloads with empty execution:', intranetResult.emptyExecutionIds);
