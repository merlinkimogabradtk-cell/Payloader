
const fs = require('fs');

const webPayloadsFile = 'src/data/webPayloads.ts';
const intranetPayloadsFile = 'src/data/intranetPayloads.ts';

function checkPayloadQuality(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n');
  let currentId = null;
  const issues = [];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const idMatch = line.match(/id:\s*'([^']+)'/);
    if (idMatch) {
      currentId = idMatch[1];
    }
    
    // Crude check for execution array
    if (currentId) {
      // We can't easily parse the full object here without a parser.
      // But we can look for "execution: [" and count items? No.
      // We can look for "syntaxBreakdown: [" and count occurrences per ID?
      // Or just find IDs that lack "syntaxBreakdown".
      
      // Let's use a simpler heuristic:
      // If we see "execution: [" and then multiple "title:" but no "syntaxBreakdown:", that's bad.
    }
  }
  
  // Better approach: regex to find the entire payload block and analyze it.
  // But payload blocks are multi-line and nested.
  
  // Let's use regex to find each payload object (roughly).
  // Assuming they start with { and end with }, but they are inside an array.
  // It's hard to parse with regex.
  
  // Alternative: Extract all `id`s. For each ID, check if the file content *after* that ID (until the next ID) contains `syntaxBreakdown`.
  // If not, report it.
}

function checkSyntaxBreakdown(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const idRegex = /id:\s*'([^']+)'/g;
  let match;
  const ids = [];
  while ((match = idRegex.exec(content)) !== null) {
    ids.push({ id: match[1], index: match.index });
  }
  
  const issues = [];
  for (let i = 0; i < ids.length; i++) {
    const current = ids[i];
    const next = ids[i + 1];
    const end = next ? next.index : content.length;
    const payloadContent = content.substring(current.index, end);
    
    // Check if it has execution
    if (!payloadContent.includes('execution: [')) {
       // Only report if it's not a category-only item (unlikely for payloads)
       // But wait, some might not have execution?
       issues.push({ id: current.id, type: 'Missing execution' });
    } else {
        // Check if it has syntaxBreakdown
        // Count "title:" (execution items) and "syntaxBreakdown:"
        const executionCount = (payloadContent.match(/title:/g) || []).length;
        const syntaxCount = (payloadContent.match(/syntaxBreakdown:/g) || []).length;
        
        if (executionCount > 0 && syntaxCount === 0) {
            issues.push({ id: current.id, type: 'Missing syntaxBreakdown completely' });
        } else if (executionCount > syntaxCount) {
             issues.push({ id: current.id, type: `Partial syntaxBreakdown (${syntaxCount}/${executionCount})` });
        }
    }
  }
  return issues;
}

const webIssues = checkSyntaxBreakdown(webPayloadsFile);
const intranetIssues = checkSyntaxBreakdown(intranetPayloadsFile);

console.log('Web Payload Issues:', webIssues);
console.log('Intranet Payload Issues:', intranetIssues);
