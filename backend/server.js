const express = require('express');
const cors = require('cors');
// const Anthropic = require('@anthropic-ai/sdk');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;

app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Initialize Anthropic
// const anthropic = new Anthropic({
//   apiKey: process.env.ANTHROPIC_API_KEY,
// });
const Groq = require('groq-sdk');

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY,
});


// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Text-to-SQL API is running' });
});

// Generate SQL endpoint
app.post('/api/generate-sql', async (req, res) => {
  try {
    const { question, schema, sampleData, tableName, vectorStore } = req.body;

    if (!question) {
      return res.status(400).json({ error: 'Question is required' });
    }

    // Security checks
    const securityThreats = detectPromptInjection(question);
    if (securityThreats.length > 0) {
      return res.status(400).json({ 
        error: 'Security violation detected',
        threats: securityThreats 
      });
    }

    // Prepare RAG context
    const relevantColumns = vectorStore?.filter(v => 
      question.toLowerCase().includes(v.column.toLowerCase()) ||
      v.metadata?.distinctValues?.some(val => 
        question.toLowerCase().includes(String(val).toLowerCase())
      )
    ) || [];

    const schemaContext = schema?.map(col => 
      `\`${col.name}\` ${col.type}`
    ).join(', ') || '';

    const sampleRows = sampleData?.slice(0, 3).map(row => 
      Object.keys(row).map(key => `\`${key}\`: ${JSON.stringify(row[key])}`).join(', ')
    ).join('\n') || '';

    // RAG-enhanced prompt
    const prompt = `You are an expert SQL query generator. Generate a syntactically correct SQL query.

DATABASE SCHEMA:
Table Name: ${tableName || 'data'}
Columns: ${schemaContext}

SAMPLE DATA (first 3 rows):
${sampleRows}

RELEVANT CONTEXT:
${relevantColumns.map(v => `- Column \`${v.column}\` (${v.type}): Sample values: ${v.metadata?.distinctValues?.slice(0, 5).join(', ') || 'N/A'}`).join('\n')}

IMPORTANT RULES:
1. ALWAYS use backticks around column names: \`Column Name\`
2. ALWAYS include the FROM clause with table name: FROM ${tableName || 'data'}
3. Use exact column names from schema (case-sensitive)
4. Use proper SQL syntax: SELECT \`col1\`, \`col2\` FROM ${tableName || 'data'} WHERE \`col3\` = 'value'
5. Return ONLY the SQL query, no explanations

FEW-SHOT EXAMPLES:
Q: "Find rank of Nepal"
A: SELECT \`Country\`, \`Year\`, \`Rank\` FROM ${tableName || 'data'} WHERE \`Country\` = 'Nepal'

Q: "Total sales in 2024"
A: SELECT SUM(\`Sales\`) as total_sales FROM ${tableName || 'data'} WHERE \`Year\` = 2024

Q: "Average price of products"
A: SELECT AVG(\`Price\`) as avg_price FROM ${tableName || 'data'}

USER QUESTION: "${question}"

Generate the SQL query now:`;

    // Call Anthropic API
    // const response = await anthropic.messages.create({
    //   model: "claude-3-5-sonnet-20241022",
    //   max_tokens: 1500,
    //   temperature: 0.1,
    //   messages: [
    //     { role: "user", content: prompt }
    //   ],
    // });

    // let sqlQuery = response.content[0].text.trim();
    const completion = await groq.chat.completions.create({
  model: "llama-3.3-70b-versatile",
  messages: [
    {
      role: "system",
      content: "You are an expert SQL query generator. Return ONLY valid SQL. No explanations."
    },
    {
      role: "user",
      content: prompt
    }
  ],
  temperature: 0.1,
  max_tokens: 1000
});

let sqlQuery = completion.choices[0].message.content.trim();

    // Clean up markdown formatting
    sqlQuery = sqlQuery.replace(/```sql\n?/g, '').replace(/```\n?/g, '').trim();
    
    // Remove any explanatory text
    const lines = sqlQuery.split('\n');
    sqlQuery = lines.find(line => line.trim().toUpperCase().startsWith('SELECT')) || sqlQuery;
    
    // Validate SQL grammar
    const grammarErrors = validateSQLGrammar(sqlQuery);
    if (grammarErrors.length > 0) {
      return res.status(400).json({ 
        error: 'SQL grammar error',
        details: grammarErrors 
      });
    }

    res.json({ 
      sql: sqlQuery.trim(),
      metadata: {
        model: "claude-3-5-sonnet",
        securityChecked: true,
        grammarValidated: true,
        ragUsed: relevantColumns.length > 0
      }
    });

  } catch (error) {
    console.error('Error generating SQL:', error);
    res.status(500).json({ 
      error: 'Failed to generate SQL',
      details: error.message 
    });
  }
});

// Security functions
function detectPromptInjection(query) {
  const threats = [];
  const suspiciousPatterns = [
    { pattern: /ignore\s+(previous|above|all)\s+instructions?/i, threat: 'Instruction Override Attempt' },
    { pattern: /system\s*:\s*you\s+are/i, threat: 'System Role Hijacking' },
    { pattern: /\/\*|\*\/|--|#/g, threat: 'SQL Comment Injection' },
    { pattern: /;\s*(drop|delete|truncate|insert|update)\s+/i, threat: 'SQL Injection Attack' },
    { pattern: /(union|union\s+all)\s+select/i, threat: 'UNION-based SQL Injection' },
    { pattern: /'\s*or\s+'?1'?\s*=\s*'?1/i, threat: 'Authentication Bypass Attempt' },
    { pattern: /(exec|execute|eval|script)/i, threat: 'Code Execution Attempt' },
    { pattern: /<script|javascript:|onerror=/i, threat: 'XSS Injection Attempt' },
    { pattern: /\$\{|\{\{|<%/g, threat: 'Template Injection' }
  ];

  for (const { pattern, threat } of suspiciousPatterns) {
    if (pattern.test(query)) {
      threats.push(threat);
    }
  }

  return threats;
}

function validateSQLGrammar(sql) {
  const errors = [];
  
  if (!sql.match(/FROM\s+`?\w+`?/i)) {
    errors.push('Missing FROM clause');
  }
  
  const backticks = (sql.match(/`/g) || []).length;
  if (backticks % 2 !== 0) {
    errors.push('Unbalanced backticks');
  }
  
  if (!sql.match(/^SELECT\s+/i)) {
    errors.push('Query must start with SELECT');
  }
  
  if (sql.match(/WHERE.*?(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER)/i)) {
    errors.push('Dangerous SQL operation detected');
  }
  
  return errors;
}

// Start server
app.listen(port, () => {
  console.log(`Backend API running on port ${port}`);
});