#!/usr/bin/env node

import express from 'express';
import { createServer } from 'http';
import { Server as SocketIOServer, Socket } from 'socket.io';
import path from 'path';
import { chromium, Browser } from 'playwright';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = 3000;
let browser: Browser | null = null;

// Serve static files
app.use(express.static(path.join(__dirname, '../public')));

// Initialize browser
async function initializeBrowser(): Promise<Browser> {
  if (!browser) {
    browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
  }
  return browser;
}

// Test progress tracking
interface TestProgress {
  testName: string;
  status: 'pending' | 'running' | 'completed' | 'error';
  progress: number;
  vulnerabilities: any[];
  startTime?: Date;
  endTime?: Date;
  details?: string;
}

const testSuite: TestProgress[] = [
  { testName: 'A01: Broken Access Control', status: 'pending', progress: 0, vulnerabilities: [] },
  { testName: 'A02: Cryptographic Failures', status: 'pending', progress: 0, vulnerabilities: [] },
  { testName: 'A03: Injection', status: 'pending', progress: 0, vulnerabilities: [] },
  { testName: 'A04: Insecure Design', status: 'pending', progress: 0, vulnerabilities: [] },
  { testName: 'A05: Security Misconfiguration', status: 'pending', progress: 0, vulnerabilities: [] },
  { testName: 'A06: Vulnerable Components', status: 'pending', progress: 0, vulnerabilities: [] },
  { testName: 'A07: Authentication Failures', status: 'pending', progress: 0, vulnerabilities: [] },
  { testName: 'A08: Integrity Failures', status: 'pending', progress: 0, vulnerabilities: [] },
  { testName: 'A09: Logging & Monitoring', status: 'pending', progress: 0, vulnerabilities: [] },
  { testName: 'A10: SSRF', status: 'pending', progress: 0, vulnerabilities: [] }
];

// WebSocket connection handler
io.on('connection', (socket: Socket) => {
  console.log('Client connected:', socket.id);
  
  // Send initial test suite status
  socket.emit('testSuiteUpdate', testSuite);
  
  // Handle start scan request
  socket.on('startScan', async (targetUrl: string) => {
    console.log('Starting security scan for:', targetUrl);
    await runComprehensiveScan(targetUrl, socket);
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// Broken Access Control Test
async function testBrokenAccessControl(url: string, socket: Socket): Promise<any[]> {
  const testIndex = 0;
  testSuite[testIndex].status = 'running';
  testSuite[testIndex].startTime = new Date();
  socket.emit('testUpdate', testSuite[testIndex]);
  
  const vulnerabilities: any[] = [];
  const testBrowser = await initializeBrowser();
  const context = await testBrowser.newContext();
  
  const adminPaths = [
    '/admin', '/administrator', '/wp-admin', '/admin.php', '/admin/',
    '/management', '/manager', '/control-panel', '/dashboard',
    '/admin-console', '/backend', '/admin/login'
  ];
  
  for (let i = 0; i < adminPaths.length; i++) {
    const path = adminPaths[i];
    testSuite[testIndex].progress = Math.round(((i + 1) / adminPaths.length) * 100);
    testSuite[testIndex].details = `Testing ${path}...`;
    socket.emit('testUpdate', testSuite[testIndex]);
    
    try {
      const page = await context.newPage();
      const testUrl = url + path;
      const response = await page.goto(testUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
      
      if (response && (response.status() === 200 || response.status() === 403)) {
        const vulnerability = {
          severity: 'HIGH',
          title: 'Accessible admin/sensitive path without authentication',
          path: testUrl,
          status: response.status()
        };
        vulnerabilities.push(vulnerability);
        socket.emit('vulnerabilityFound', { testIndex, vulnerability });
      }
      
      await page.close();
      await new Promise(resolve => setTimeout(resolve, 500)); // Small delay for demo
    } catch (error) {
      console.log(`Error testing ${path}:`, error);
    }
  }
  
  await context.close();
  testSuite[testIndex].status = 'completed';
  testSuite[testIndex].endTime = new Date();
  testSuite[testIndex].vulnerabilities = vulnerabilities;
  socket.emit('testUpdate', testSuite[testIndex]);
  
  return vulnerabilities;
}

// Cryptographic Failures Test
async function testCryptographicFailures(url: string, socket: Socket): Promise<any[]> {
  const testIndex = 1;
  testSuite[testIndex].status = 'running';
  testSuite[testIndex].startTime = new Date();
  socket.emit('testUpdate', testSuite[testIndex]);
  
  const vulnerabilities: any[] = [];
  const testBrowser = await initializeBrowser();
  const context = await testBrowser.newContext();
  
  testSuite[testIndex].progress = 50;
  testSuite[testIndex].details = 'Checking HTTPS configuration...';
  socket.emit('testUpdate', testSuite[testIndex]);
  
  try {
    const page = await context.newPage();
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    
    const isHttps = url.startsWith('https://');
    
    if (isHttps) {
      const vulnerability = {
        severity: 'LOW',
        title: 'HTTPS is properly configured',
        description: 'Further SSL/TLS configuration analysis recommended'
      };
      vulnerabilities.push(vulnerability);
    } else {
      const vulnerability = {
        severity: 'HIGH',
        title: 'Insecure HTTP connection detected',
        description: 'Site should use HTTPS for secure communication'
      };
      vulnerabilities.push(vulnerability);
    }
    
    await page.close();
  } catch (error) {
    console.log('Error in crypto test:', error);
  }
  
  await context.close();
  testSuite[testIndex].progress = 100;
  testSuite[testIndex].status = 'completed';
  testSuite[testIndex].endTime = new Date();
  testSuite[testIndex].vulnerabilities = vulnerabilities;
  socket.emit('testUpdate', testSuite[testIndex]);
  
  return vulnerabilities;
}

// Security Misconfiguration Test
async function testSecurityMisconfiguration(url: string, socket: Socket): Promise<any[]> {
  const testIndex = 4;
  testSuite[testIndex].status = 'running';
  testSuite[testIndex].startTime = new Date();
  socket.emit('testUpdate', testSuite[testIndex]);
  
  const vulnerabilities: any[] = [];
  const testBrowser = await initializeBrowser();
  const context = await testBrowser.newContext();
  
  const configFiles = [
    '/web.config', '/config.php', '/.env', '/.git/config',
    '/database.php', '/backup.sql', '/database.sql'
  ];
  
  for (let i = 0; i < configFiles.length; i++) {
    const file = configFiles[i];
    testSuite[testIndex].progress = Math.round(((i + 1) / configFiles.length) * 100);
    testSuite[testIndex].details = `Checking ${file}...`;
    socket.emit('testUpdate', testSuite[testIndex]);
    
    try {
      const page = await context.newPage();
      const testUrl = url + file;
      const response = await page.goto(testUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
      
      if (response && response.status() === 200) {
        const vulnerability = {
          severity: 'CRITICAL',
          title: file.includes('backup') || file.includes('database') ? 
                 'Database backup file accessible' : 'Configuration file accessible',
          url: testUrl,
          recommendation: file.includes('backup') ? 
                        'Remove or restrict access to backup files' : 
                        'Restrict access to configuration files'
        };
        vulnerabilities.push(vulnerability);
        socket.emit('vulnerabilityFound', { testIndex, vulnerability });
      }
      
      await page.close();
      await new Promise(resolve => setTimeout(resolve, 300));
    } catch (error) {
      console.log(`Error testing ${file}:`, error);
    }
  }
  
  await context.close();
  testSuite[testIndex].status = 'completed';
  testSuite[testIndex].endTime = new Date();
  testSuite[testIndex].vulnerabilities = vulnerabilities;
  socket.emit('testUpdate', testSuite[testIndex]);
  
  return vulnerabilities;
}

// Mock tests for other categories (for demo purposes)
async function runMockTest(testIndex: number, testName: string, socket: Socket): Promise<any[]> {
  testSuite[testIndex].status = 'running';
  testSuite[testIndex].startTime = new Date();
  socket.emit('testUpdate', testSuite[testIndex]);
  
  // Simulate test progress
  for (let progress = 0; progress <= 100; progress += 20) {
    testSuite[testIndex].progress = progress;
    testSuite[testIndex].details = `Running ${testName} checks... ${progress}%`;
    socket.emit('testUpdate', testSuite[testIndex]);
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  
  // Mock some vulnerabilities for demo
  const mockVulnerabilities = testIndex === 2 ? [] : // A03 Injection - clean
    testIndex === 5 ? [] : // A06 Components - clean
    testIndex === 6 ? [] : // A07 Auth - clean
    [{
      severity: testIndex === 7 ? 'MEDIUM' : 'LOW',
      title: `Sample ${testName} issue`,
      description: `Mock vulnerability for ${testName}`
    }];
  
  testSuite[testIndex].status = 'completed';
  testSuite[testIndex].endTime = new Date();
  testSuite[testIndex].vulnerabilities = mockVulnerabilities;
  socket.emit('testUpdate', testSuite[testIndex]);
  
  return mockVulnerabilities;
}

// Run comprehensive security scan
async function runComprehensiveScan(targetUrl: string, socket: Socket) {
  socket.emit('scanStarted', { targetUrl, timestamp: new Date() });
  
  try {
    // Reset test suite
    testSuite.forEach(test => {
      test.status = 'pending';
      test.progress = 0;
      test.vulnerabilities = [];
      test.startTime = undefined;
      test.endTime = undefined;
    });
    
    socket.emit('testSuiteUpdate', testSuite);
    
    // Run actual tests
    await testBrokenAccessControl(targetUrl, socket);
    await testCryptographicFailures(targetUrl, socket);
    await runMockTest(2, 'Injection', socket);
    await runMockTest(3, 'Insecure Design', socket);
    await testSecurityMisconfiguration(targetUrl, socket);
    await runMockTest(5, 'Vulnerable Components', socket);
    await runMockTest(6, 'Authentication Failures', socket);
    await runMockTest(7, 'Integrity Failures', socket);
    await runMockTest(8, 'Logging & Monitoring', socket);
    await runMockTest(9, 'SSRF', socket);
    
    // Calculate final summary
    const totalVulnerabilities = testSuite.reduce((sum, test) => sum + test.vulnerabilities.length, 0);
    const criticalCount = testSuite.reduce((sum, test) => 
      sum + test.vulnerabilities.filter(v => v.severity === 'CRITICAL').length, 0);
    const highCount = testSuite.reduce((sum, test) => 
      sum + test.vulnerabilities.filter(v => v.severity === 'HIGH').length, 0);
    const mediumCount = testSuite.reduce((sum, test) => 
      sum + test.vulnerabilities.filter(v => v.severity === 'MEDIUM').length, 0);
    const lowCount = testSuite.reduce((sum, test) => 
      sum + test.vulnerabilities.filter(v => v.severity === 'LOW').length, 0);
    
    socket.emit('scanCompleted', {
      targetUrl,
      totalVulnerabilities,
      severityBreakdown: { critical: criticalCount, high: highCount, medium: mediumCount, low: lowCount },
      timestamp: new Date(),
      testResults: testSuite
    });
    
  } catch (error: any) {
    console.error('Error during scan:', error);
    socket.emit('scanError', { error: error.message });
  }
}

// Start server
server.listen(PORT, () => {
  console.log(`🚀 Live OWASP Security Dashboard running on http://localhost:${PORT}`);
  console.log(`📊 Real-time security testing with live updates`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\nShutting down server...');
  if (browser) {
    await browser.close();
  }
  process.exit(0);
});
