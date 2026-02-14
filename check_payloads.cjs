
const fs = require('fs');
const path = require('path');

const files = [
  'c:/Users/Hezihao/Desktop/1/cyber-arsenal/src/data/webPayloads.ts',
  'c:/Users/Hezihao/Desktop/1/cyber-arsenal/src/data/intranetPayloads.ts'
];

files.forEach(file => {
  const content = fs.readFileSync(file, 'utf8');
  console.log(`Checking ${file}...`);
  
  const payloads = content.split(/\n\s+id:\s+'/);
  
  payloads.forEach((p, i) => {
    if (i === 0) return;
    
    const idMatch = p.match(/^([^']+)/);
    const id = idMatch ? idMatch[1] : 'unknown';
    
    if (!p.includes('execution: [')) {
      console.log(`[WARN] Payload ${id} has no execution array`);
      return;
    }
    
    // Check if empty execution array
    if (p.includes('execution: []')) {
      console.log(`[WARN] Payload ${id} has EMPTY execution array`);
      return;
    }

    const executionBlock = p.split('execution: [')[1].split('tutorial:')[0];
    const items = executionBlock.split(/title:\s+'/);
    
    items.forEach((item, j) => {
      if (j === 0) return;
      
      const titleMatch = item.match(/^([^']+)/);
      const title = titleMatch ? titleMatch[1] : 'unknown';
      
      if (!item.includes('syntaxBreakdown:')) {
        console.log(`[MISSING] Payload ${id} - Item "${title}" missing syntaxBreakdown`);
      }
    });
  });
});
