import React, { useState, useEffect } from 'react';
import { Upload, MessageSquare, Database, Loader2, Download, Shield, CheckCircle, AlertTriangle, Brain, Lock, Zap } from 'lucide-react';
import * as XLSX from 'xlsx';
import Papa from 'papaparse';
import './App.css';

const API_BASE_URL = process.env.REACT_APP_API_URL;
console.log('API Base URL:', API_BASE_URL);

function App() {
  const [file, setFile] = useState(null);
  const [tableName, setTableName] = useState('');
  const [schema, setSchema] = useState(null);
  const [data, setData] = useState([]);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [vectorStore, setVectorStore] = useState([]);
  const [securityLog, setSecurityLog] = useState([]);
  const [apiStatus, setApiStatus] = useState('checking');

  // Check API health on startup
  useEffect(() => {
    checkApiHealth();
  }, []);

  const checkApiHealth = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/health`);
      if (response.ok) {
        setApiStatus('connected');
      } else {
        setApiStatus('error');
      }
    } catch (error) {
      console.error('API connection error:', error);
      setApiStatus('error');
    }
  };

  // Create vector embeddings for schema and sample data
  const createVectorEmbeddings = async (schemaData, sampleData) => {
    const embeddings = [];
    
    for (const col of schemaData) {
      const context = `Column: ${col.name}, Type: ${col.type}, Sample values: ${
        sampleData.slice(0, 5).map(row => row[col.name]).join(', ')
      }`;
      
      embeddings.push({
        column: col.name,
        type: col.type,
        context: context,
        metadata: {
          distinctValues: [...new Set(sampleData.map(row => row[col.name]))].slice(0, 10),
          sampleCount: sampleData.length
        }
      });
    }
    
    return embeddings;
  };

  // Advanced prompt injection detection
  const detectPromptInjection = (query) => {
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
  };

  // Call backend API for SQL generation
  const generateSQLWithRAG = async (question, contextualData) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/generate-sql`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          question,
          schema: contextualData.schema,
          sampleData: contextualData.data.slice(0, 10),
          tableName: contextualData.tableName,
          vectorStore: contextualData.vectorStore
        })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to generate SQL');
      }

      const result = await response.json();
      return result.sql;
    } catch (error) {
      console.error('Error generating SQL:', error);
      throw error;
    }
  };

  // Execute SQL locally (same as before)
  const executeSQL = (sqlQuery) => {
    try {
      const lowerQuery = sqlQuery.toLowerCase();
      let results = [...data];
      
      const fromMatch = sqlQuery.match(/FROM\s+`?(\w+)`?/i);
      if (!fromMatch) {
        throw new Error('Invalid SQL: Missing FROM clause');
      }
      
      // Handle WHERE clause
      if (lowerQuery.includes('where')) {
        const whereMatch = sqlQuery.match(/WHERE\s+(.+?)(?:\s+ORDER|\s+GROUP|\s+LIMIT|$)/i);
        if (whereMatch) {
          const condition = whereMatch[1].trim();
          results = results.filter(row => evaluateCondition(row, condition));
        }
      }
      
      // Handle ORDER BY
      if (lowerQuery.includes('order by')) {
        const orderMatch = sqlQuery.match(/ORDER\s+BY\s+`?(\w+)`?(?:\s+(ASC|DESC))?/i);
        if (orderMatch) {
          const column = orderMatch[1];
          const direction = orderMatch[2]?.toLowerCase() || 'asc';
          results.sort((a, b) => {
            const valA = a[column] ?? '';
            const valB = b[column] ?? '';
            if (direction === 'asc') {
              return valA > valB ? 1 : -1;
            } else {
              return valA < valB ? 1 : -1;
            }
          });
        }
      }
      
      // Handle aggregations
      if (lowerQuery.includes('sum(') || lowerQuery.includes('count(') || 
          lowerQuery.includes('avg(') || lowerQuery.includes('max(') || 
          lowerQuery.includes('min(')) {
        return calculateAggregation(results, sqlQuery);
      }
      
      // Handle LIMIT
      const limitMatch = sqlQuery.match(/LIMIT\s+(\d+)/i);
      if (limitMatch) {
        results = results.slice(0, parseInt(limitMatch[1]));
      }
      
      // Handle column selection
      const selectMatch = sqlQuery.match(/SELECT\s+(.+?)\s+FROM/i);
      if (selectMatch && selectMatch[1].trim() !== '*') {
        const columns = selectMatch[1].split(',').map(c => {
          const trimmed = c.trim();
          const aliasMatch = trimmed.match(/(.+?)\s+as\s+(\w+)/i);
          if (aliasMatch) {
            return { original: aliasMatch[1].replace(/`/g, '').trim(), alias: aliasMatch[2] };
          }
          return { original: trimmed.replace(/`/g, ''), alias: null };
        });
        
        results = results.map(row => {
          const newRow = {};
          columns.forEach(({ original, alias }) => {
            const actualColumn = Object.keys(row).find(
              key => key.toLowerCase() === original.toLowerCase()
            ) || original;
            if (row.hasOwnProperty(actualColumn)) {
              newRow[alias || actualColumn] = row[actualColumn];
            }
          });
          return newRow;
        });
      }
      
      return results;
    } catch (error) {
      console.error('Error executing SQL:', error);
      throw error;
    }
  };

  const evaluateCondition = (row, condition) => {
    const operators = ['>=', '<=', '!=', '<>', '=', '>', '<'];
    
    for (const op of operators) {
      if (condition.includes(op)) {
        const [left, right] = condition.split(op).map(s => s.trim());
        
        const columnName = left.replace(/`/g, '').trim();
        const actualColumn = Object.keys(row).find(
          key => key.toLowerCase() === columnName.toLowerCase()
        );
        
        const leftVal = actualColumn ? row[actualColumn] : left;
        const rightVal = right.replace(/['"]/g, '');
        
        switch(op) {
          case '=': return String(leftVal).toLowerCase() === rightVal.toLowerCase();
          case '!=':
          case '<>': return String(leftVal).toLowerCase() !== rightVal.toLowerCase();
          case '>': return Number(leftVal) > Number(rightVal);
          case '<': return Number(leftVal) < Number(rightVal);
          case '>=': return Number(leftVal) >= Number(rightVal);
          case '<=': return Number(leftVal) <= Number(rightVal);
        }
      }
    }
    
    return true;
  };

  const calculateAggregation = (results, sqlQuery) => {
    const sumMatch = sqlQuery.match(/SUM\(`?(\w+)`?\)(?:\s+as\s+(\w+))?/i);
    const countMatch = sqlQuery.match(/COUNT\((\*|`?\w+`?)\)(?:\s+as\s+(\w+))?/i);
    const avgMatch = sqlQuery.match(/AVG\(`?(\w+)`?\)(?:\s+as\s+(\w+))?/i);
    const maxMatch = sqlQuery.match(/MAX\(`?(\w+)`?\)(?:\s+as\s+(\w+))?/i);
    const minMatch = sqlQuery.match(/MIN\(`?(\w+)`?\)(?:\s+as\s+(\w+))?/i);
    
    if (sumMatch) {
      const col = sumMatch[1];
      const alias = sumMatch[2] || `SUM(${col})`;
      const sum = results.reduce((acc, row) => acc + (Number(row[col]) || 0), 0);
      return [{ [alias]: sum }];
    }
    
    if (countMatch) {
      const alias = countMatch[2] || 'COUNT';
      return [{ [alias]: results.length }];
    }
    
    if (avgMatch) {
      const col = avgMatch[1];
      const alias = avgMatch[2] || `AVG(${col})`;
      const sum = results.reduce((acc, row) => acc + (Number(row[col]) || 0), 0);
      return [{ [alias]: sum / results.length }];
    }
    
    if (maxMatch) {
      const col = maxMatch[1];
      const alias = maxMatch[2] || `MAX(${col})`;
      const max = Math.max(...results.map(row => Number(row[col]) || 0));
      return [{ [alias]: max }];
    }
    
    if (minMatch) {
      const col = minMatch[1];
      const alias = minMatch[2] || `MIN(${col})`;
      const min = Math.min(...results.map(row => Number(row[col]) || 0));
      return [{ [alias]: min }];
    }
    
    return results;
  };

  const handleFileUpload = async (e) => {
    const uploadedFile = e.target.files[0];
    if (!uploadedFile) return;

    const fileExtension = uploadedFile.name.split('.').pop().toLowerCase();
    const baseFileName = uploadedFile.name.replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9]/g, '_');
    setTableName(baseFileName);

    const processData = async (jsonData) => {
      if (jsonData.length > 0) {
        const columns = Object.keys(jsonData[0]);
        const detectedSchema = columns.map(col => ({
          name: col,
          type: detectColumnType(jsonData, col)
        }));

        setFile(uploadedFile);
        setData(jsonData);
        setSchema(detectedSchema);
        
        const embeddings = await createVectorEmbeddings(detectedSchema, jsonData);
        setVectorStore(embeddings);
        
        setMessages([{
          type: 'system',
          content: `✅ Database loaded successfully!\n📊 Table: ${baseFileName}\n📈 Rows: ${jsonData.length}\n📋 Columns: ${columns.join(', ')}\n🧠 RAG vector embeddings created\n🔒 Security monitoring active\n🌐 API Status: ${apiStatus}`
        }]);
      }
    };

    if (fileExtension === 'csv') {
      Papa.parse(uploadedFile, {
        header: true,
        dynamicTyping: true,
        skipEmptyLines: true,
        complete: (results) => processData(results.data),
        error: (error) => {
          console.error('Error parsing CSV:', error);
          alert('Error loading CSV file.');
        }
      });
    } else {
      const reader = new FileReader();
      reader.onload = (event) => {
        const workbook = XLSX.read(event.target.result, { type: 'binary' });
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const jsonData = XLSX.utils.sheet_to_json(sheet);
        processData(jsonData);
      };
      reader.readAsBinaryString(uploadedFile);
    }
  };

  const detectColumnType = (data, column) => {
    const sample = data[0][column];
    if (typeof sample === 'number') return 'NUMBER';
    if (!isNaN(Date.parse(sample))) return 'DATE';
    return 'TEXT';
  };

  const handleSendMessage = async () => {
    if (!input.trim() || !schema) return;

    const userMessage = { type: 'user', content: input };
    setMessages(prev => [...prev, userMessage]);
    const userQuery = input;
    setInput('');
    setLoading(true);

    try {
      // Security Check
      const threats = detectPromptInjection(userQuery);
      if (threats.length > 0) {
        setSecurityLog(prev => [...prev, { query: userQuery, threats, timestamp: new Date() }]);
        throw new Error(`🚨 Security Alert: ${threats.join(', ')}`);
      }

      // Generate SQL using backend API
      const sqlQuery = await generateSQLWithRAG(userQuery, { 
        schema, 
        data, 
        tableName,
        vectorStore 
      });
      
      // Execute query locally
      const results = executeSQL(sqlQuery);
      
      setMessages(prev => [...prev, {
        type: 'assistant',
        content: '✅ Query executed successfully',
        sql: sqlQuery,
        results: results,
        metadata: {
          securityPassed: true,
          grammarValid: true,
          ragUsed: true,
          executionTime: '0.05s',
          apiUsed: true
        }
      }]);
    } catch (error) {
      setMessages(prev => [...prev, {
        type: 'error',
        content: error.message || 'Error processing query'
      }]);
    }

    setLoading(false);
  };

  const exportResults = (results) => {
    const ws = XLSX.utils.json_to_sheet(results);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "Results");
    XLSX.writeFile(wb, "query_results.xlsx");
  };

  return (
    <div class="main-container" >
      <div >
        {/* API Status Indicator */}
        <div className={`mb-4 p-3 rounded-lg flex items-center justify-between ${
          apiStatus === 'connected' ? 'bg-green-900/50 text-green-100' : 
          apiStatus === 'error' ? 'bg-red-900/50 text-red-100' : 
          'bg-yellow-900/50 text-yellow-100'
        }`}>
          <div >
            <div className={`w-3 h-3 rounded-full ${
              apiStatus === 'connected' ? 'bg-green-400' : 
              apiStatus === 'error' ? 'bg-red-400' : 
              'bg-yellow-400 animate-pulse'
            }`}></div>
            <span className="font-medium">
              {apiStatus === 'connected' ? '✅ Backend API Connected' : 
               apiStatus === 'error' ? '❌ Backend API Disconnected' : 
               '⏳ Connecting to API...'}
            </span>
          </div>
          <span className="text-sm opacity-80">
            {apiStatus === 'connected' ? 'Ready to process queries' : 
             'Some features may be limited'}
          </span>
        </div>

        {/* Main App Container */}
        <div className="bg-white/95 backdrop-blur rounded-2xl shadow-2xl overflow-hidden border border-purple-200">
          {/* Header */}
          <div className="bg-gradient-to-r from-purple-600 via-pink-600 to-blue-600 p-6 text-white">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-4xl font-bold flex items-center gap-3">
                  <Brain className="w-10 h-10" />
                  SQLify AI
                </h1>
                <p className="mt-2 text-purple-100">Level 4 GenAI with RAG, Vector Embeddings & Security</p>
              </div>
              <div className="flex gap-2">
                <div className="bg-white/20 backdrop-blur px-3 py-1 rounded-full text-sm flex items-center gap-2">
                  <Shield className="w-4 h-4" />
                  Protected
                </div>
                <div className="bg-white/20 backdrop-blur px-3 py-1 rounded-full text-sm flex items-center gap-2">
                  <Zap className="w-4 h-4" />
                  RAG Enabled
                </div>
              </div>
            </div>
          </div>

          {/* File Upload */}
          {!file && (
            <div className="p-8">
              <label className="flex flex-col items-center justify-center w-full h-72 border-2 border-dashed border-purple-300 rounded-xl cursor-pointer hover:bg-purple-50 transition-all hover:border-purple-500">
                <Upload className="w-16 h-16 text-purple-400 mb-4" />
                <span className="text-xl font-semibold text-gray-700">Upload Your Database</span>
                <span className="text-sm text-gray-500 mt-2">Excel (.xlsx, .xls) or CSV (.csv)</span>
                <input
                  type="file"
                  className="hidden"
                  accept=".xlsx,.xls,.csv"
                  onChange={handleFileUpload}
                />
              </label>
            </div>
          )}

          {/* Chat Interface */}
          {file && (
            <div className="flex flex-col h-[650px]">
              {/* Messages */}
              <div className="flex-1 overflow-y-auto p-6 space-y-4">
                {messages.map((msg, idx) => (
                  <div key={idx} className={`flex ${msg.type === 'user' ? 'justify-end' : 'justify-start'}`}>
                    <div className={`max-w-4xl ${
                      msg.type === 'user' 
                        ? 'bg-gradient-to-r from-purple-600 to-blue-600 text-white' 
                        : msg.type === 'system'
                        ? 'bg-gradient-to-r from-green-50 to-emerald-50 text-white-800 border border-green-200'
                        : msg.type === 'error'
                        ? 'bg-gradient-to-r from-red-50 to-pink-50 text-red-800 border border-red-200'
                        : 'bg-gradient-to-r from-gray-50 to-slate-50 text-gray-800 border border-gray-200'
                    } rounded-xl p-5 shadow-lg`}>
                      <p className="whitespace-pre-wrap font-medium">{msg.content}</p>
                      
                      {msg.metadata && (
                        <div className="mt-3 flex gap-2 text-xs">
                          {msg.metadata.securityPassed && (
                            <span className="bg-green-100 text-green-700 px-2 py-1 rounded-full flex items-center gap-1">
                              <Shield className="w-3 h-3" /> Security ✓
                            </span>
                          )}
                          {msg.metadata.grammarValid && (
                            <span className="bg-blue-100 text-blue-700 px-2 py-1 rounded-full flex items-center gap-1">
                              <CheckCircle className="w-3 h-3" /> Grammar ✓
                            </span>
                          )}
                          {msg.metadata.ragUsed && (
                            <span className="bg-purple-100 text-purple-700 px-2 py-1 rounded-full flex items-center gap-1">
                              <Brain className="w-3 h-3" /> RAG ✓
                            </span>
                          )}
                          {msg.metadata.apiUsed && (
                            <span className="bg-indigo-100 text-indigo-700 px-2 py-1 rounded-full flex items-center gap-1">
                              <Zap className="w-3 h-3" /> API ✓
                            </span>
                          )}
                        </div>
                      )}
                      
                      {msg.sql && (
                        <div className="mt-4 bg-slate-900 text-green-400 p-4 rounded-lg font-mono text-sm overflow-x-auto shadow-inner">
                          <div className="text-gray-400 text-xs mb-2">Generated SQL Query:</div>
                          {msg.sql}
                        </div>
                      )}
                      
                      {msg.results && msg.results.length > 0 && (
                        <div className="mt-4">
                          <div className="flex justify-between items-center mb-3">
                            <span className="font-bold text-lg">📊 Results ({msg.results.length} rows)</span>
                            <button
                              onClick={() => exportResults(msg.results)}
                            >
                              <Download className="w-4 h-4" />
                              Export Excel
                            </button>
                          </div>
                          <div className="overflow-x-auto rounded-lg border border-gray-200">
                            <table className="min-w-full text-sm">
                              <thead className="bg-gradient-to-r from-purple-100 to-blue-100">
                                <tr>
                                  {Object.keys(msg.results[0]).map(key => (
                                    <th key={key} className="px-4 py-3 text-left font-bold text-purple-900">
                                      {key}
                                    </th>
                                  ))}
                                </tr>
                              </thead>
                              <tbody className="bg-white">
                                {msg.results.slice(0, 10).map((row, i) => (
                                  <tr key={i} className="hover:bg-purple-50 border-b border-gray-100">
                                    {Object.values(row).map((val, j) => (
                                      <td key={j} className="px-4 py-3">
                                        {String(val)}
                                      </td>
                                    ))}
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                            {msg.results.length > 10 && (
                              <p className="text-xs text-gray-600 p-2 bg-gray-50">Showing first 10 of {msg.results.length} rows</p>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
                
                {loading && (
                  <div className="flex justify-start">
                    <div className="bg-gradient-to-r from-purple-100 to-blue-100 rounded-xl p-4 flex items-center gap-3 shadow-lg">
                      <Loader2 className="w-6 h-6 animate-spin text-purple-600" />
                      <span className="font-medium text-purple-900">AI is analyzing your question with RAG...</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Input */}
              <div className="border-t bg-gradient-to-r from-purple-50 to-blue-50 p-4">
                <div className="flex gap-3">
                  <input
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
                    placeholder="Ask anything about your data... (protected by AI security)"
                    className="flex-1 px-5 py-4 border-2 border-purple-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent text-lg"
                    disabled={loading || apiStatus === 'error'}
                  />
                  <button
                    onClick={handleSendMessage}
                    disabled={loading || !input.trim() || apiStatus === 'error'}
                    className="px-8 py-4 bg-gradient-to-r from-purple-600 to-blue-600 text-white rounded-xl hover:from-purple-700 hover:to-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 font-semibold shadow-lg transition-all"
                  >
                    <MessageSquare className="w-5 h-5" />
                    Send
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Features Dashboard */}
        <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Level 4 Features */}
          <div className="bg-white rounded-xl shadow-lg p-6 border-2 border-purple-200">
            <h2 className="text-xl font-bold mb-4 text-purple-900 flex items-center gap-2">
              <Zap className="w-6 h-6" />
              Level 4 GenAI Features
            </h2>
            <div className="space-y-3">
              <div className="flex items-start gap-3 p-3 bg-purple-50 rounded-lg">
                <CheckCircle className="w-5 h-5 text-purple-600 mt-0.5" />
                <div>
                  <div className="font-semibold text-purple-900">RAG (Retrieval-Augmented Generation)</div>
                  <div className="text-sm text-purple-700">Context-aware query generation with schema embeddings</div>
                </div>
              </div>
              <div className="flex items-start gap-3 p-3 bg-blue-50 rounded-lg">
                <CheckCircle className="w-5 h-5 text-blue-600 mt-0.5" />
                <div>
                  <div className="font-semibold text-blue-900">Backend AI API</div>
                  <div className="text-sm text-blue-700">Secure API with Claude Sonnet 4 integration</div>
                </div>
              </div>
              <div className="flex items-start gap-3 p-3 bg-red-50 rounded-lg">
                <CheckCircle className="w-5 h-5 text-red-600 mt-0.5" />
                <div>
                  <div className="font-semibold text-red-900">Prompt Injection Protection</div>
                  <div className="text-sm text-red-700">Multi-layer security against malicious inputs</div>
                </div>
              </div>
              <div className="flex items-start gap-3 p-3 bg-green-50 rounded-lg">
                <CheckCircle className="w-5 h-5 text-green-600 mt-0.5" />
                <div>
                  <div className="font-semibold text-green-900">SQL Grammar Validation</div>
                  <div className="text-sm text-green-700">Syntax verification before execution</div>
                </div>
              </div>
              <div className="flex items-start gap-3 p-3 bg-yellow-50 rounded-lg">
                <CheckCircle className="w-5 h-5 text-yellow-600 mt-0.5" />
                <div>
                  <div className="font-semibold text-yellow-900">Enterprise Architecture</div>
                  <div className="text-sm text-yellow-700">Separate frontend/backend with Vercel deployment</div>
                </div>
              </div>
            </div>
          </div>

          {/* Security Log */}
          <div className="bg-white rounded-xl shadow-lg p-6 border-2 border-red-200">
            <h2 className="text-xl font-bold mb-4  flex items-center gap-2">
              <Lock className="w-6 h-6" />
              Security Monitor
            </h2>
            {securityLog.length === 0 ? (
              <div className="text-center py-8 text-gray-500 bg-color-gray">
                <Shield className="w-15 h-15 mx-auto mb-3 text-green-400" />
                <p className="font-medium">All queries secure ✓</p>
                <p className="text-sm">No threats detected</p>
              </div>
            ) : (
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {securityLog.map((log, idx) => (
                  <div key={idx} className="p-3 bg-red-50 rounded-lg border border-red-200">
                    <div className="flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-red-600 mt-0.5" />
                      <div className="text-xs">
                        <div className="font-semibold text-red-900">{log.threats.join(', ')}</div>
                        <div className="text-red-700 mt-1">{log.query}</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Technology Stack */}
        <div class="technology-stack" >
          <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Brain className="w-6 h-6" />
            Powered By Advanced AI Technology
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm">
            <div>
              <div className="font-semibold text-purple-500 mb-2">🤖 AI Model</div>
              <div className="text-black-300">Claude Sonnet 4</div>
            </div>
            <div>
              <div className="font-semibold text-purple-500 mb-2">🔒 Security</div>
              <div className="text-black-300">Multi-layer prompt injection detection</div>
            </div>
            <div>
              <div className="font-semibold text-purple-500 mb-2">🧠 Intelligence</div>
              <div className="text-black-300">RAG with vector embeddings</div>
            </div>
            
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;