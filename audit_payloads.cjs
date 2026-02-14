
const fs = require('fs');
const path = require('path');

// Mock types to allow require
const webPath = path.join(__dirname, 'src', 'data', 'webPayloads.ts');
const intraPath = path.join(__dirname, 'src', 'data', 'intranetPayloads.ts');

function parsePayloads(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  // Simple regex to find payload objects. This is brittle but might work for a quick check.
  // Better approach: use a proper parser or just regex for specific fields within blocks.
  // Actually, since it's TS, we can't require it directly in Node without compilation.
  // So we have to parse text.
  
  const payloads = [];
  const lines = content.split('\n');
  let currentPayload = null;
  let inExecution = false;
  let braceCount = 0;

  // This is too complex to parse with regex/lines robustly.
  // Let's use a simpler heuristic:
  // 1. Find all `id: '...'`
  // 2. Look ahead for `execution: [`
  // 3. Check if `syntaxBreakdown` exists inside the execution block before the next payload.
  
  // Alternative: match the whole object structure with a better regex or library.
  // But for now, let's just find the IDs of payloads that might be missing things.
  
  // We can just grep for missing syntaxBreakdown.
  // But we need to know WHICH payload is missing it.
  
  return content;
}

function auditFile(filePath, type) {
  const content = fs.readFileSync(filePath, 'utf8');
  
  // Find all payload starts
  const payloadRegex = /id:\s*'([^']+)'/g;
  let match;
  const issues = [];
  
  while ((match = payloadRegex.exec(content)) !== null) {
    const id = match[1];
    const startIndex = match.index;
    
    // Find the end of this payload (heuristic: next id: or end of file)
    // This is tricky. Let's find the next 'id:'
    const nextMatch = payloadRegex.exec(content);
    const endIndex = nextMatch ? nextMatch.index : content.length;
    
    // Reset regex lastIndex for next iteration
    payloadRegex.lastIndex = nextMatch ? nextMatch.index : content.length;
    if (!nextMatch) {
        // scan from current match to end
    }

    const payloadBlock = content.substring(startIndex, endIndex);
    
    // Check for syntaxBreakdown
    // We want to verify that *every* command in execution has it?
    // Or at least *some*? User said "many payloads lack it".
    
    // Count execution items
    const execMatches = payloadBlock.match(/command:\s*['"`]/g);
    const syntaxMatches = payloadBlock.match(/syntaxBreakdown:\s*\[/g);
    
    const execCount = execMatches ? execMatches.length : 0;
    const syntaxCount = syntaxMatches ? syntaxMatches.length : 0;
    
    if (execCount > 0 && syntaxCount === 0) {
      issues.push({ id, type: 'missing_syntax_all', detail: `0/${execCount} have syntax` });
    } else if (execCount > syntaxCount) {
       // issues.push({ id, type: 'missing_syntax_partial', detail: `${syntaxCount}/${execCount} have syntax` });
    }
    
    // Check tutorial
    if (!payloadBlock.includes('tutorial: {')) {
        issues.push({ id, type: 'missing_tutorial' });
    } else {
        // Check tutorial content
        const tutMatch = payloadBlock.match(/tutorial:\s*\{([^}]+)\}/s);
        if (tutMatch) {
            const tutContent = tutMatch[1];
            if (!tutContent.includes('exploitation') && !tutContent.includes('利用流程')) {
                 issues.push({ id, type: 'weak_tutorial', detail: 'No exploitation steps' });
            }
        }
    }
  }
  return issues;
}

const webIssues = auditFile(webPath, 'Web');
const intraIssues = auditFile(intraPath, 'Intranet');

console.log('Web Issues:', webIssues);
console.log('Intranet Issues:', intraIssues);
