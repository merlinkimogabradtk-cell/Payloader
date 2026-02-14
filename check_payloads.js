
const fs = require('fs');
const path = require('path');

const files = [
  'c:/Users/Hezihao/Desktop/1/cyber-arsenal/src/data/webPayloads.ts',
  'c:/Users/Hezihao/Desktop/1/cyber-arsenal/src/data/intranetPayloads.ts'
];

files.forEach(file => {
  const content = fs.readFileSync(file, 'utf8');
  console.log(`Checking ${file}...`);
  
  // Very rough parsing - just finding objects with 'title' and 'command' inside 'execution' array
  // and checking if they have 'syntaxBreakdown'
  
  // Strategy: Split by "id:" to get payloads
  const payloads = content.split(/\n\s+id:\s+'/);
  
  payloads.forEach((p, i) => {
    if (i === 0) return; // Skip preamble
    
    const idMatch = p.match(/^([^']+)/);
    const id = idMatch ? idMatch[1] : 'unknown';
    
    // Check if execution array exists
    if (!p.includes('execution: [')) {
      console.log(`[WARN] Payload ${id} has no execution array`);
      return;
    }
    
    // Extract execution block
    const executionBlock = p.split('execution: [')[1].split('tutorial:')[0];
    
    // Split into items (rough heuristic: by "title:")
    const items = executionBlock.split(/title:\s+'/);
    
    items.forEach((item, j) => {
      if (j === 0) return; // Skip preamble of execution block
      
      const titleMatch = item.match(/^([^']+)/);
      const title = titleMatch ? titleMatch[1] : 'unknown';
      
      if (!item.includes('syntaxBreakdown:')) {
        console.log(`[MISSING] Payload ${id} - Item "${title}" missing syntaxBreakdown`);
      }
    });
  });
});
