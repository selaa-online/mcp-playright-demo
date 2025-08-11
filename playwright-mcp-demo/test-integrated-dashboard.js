#!/usr/bin/env node
import { spawn } from 'child_process';

// Test script to demonstrate the integrated MCP dashboard functionality
console.log('🚀 Testing Integrated MCP Dashboard...\n');

// Function to send MCP request
function sendMCPRequest(method, params = {}) {
  return new Promise((resolve, reject) => {
    const mcp = spawn('node', ['build/index.js'], {
      stdio: ['pipe', 'pipe', 'inherit']
    });
    
    const request = {
      jsonrpc: "2.0",
      id: 1,
      method: method,
      params: params
    };
    
    let output = '';
    
    mcp.stdout.on('data', (data) => {
      output += data.toString();
    });
    
    mcp.on('close', (code) => {
      try {
        const lines = output.trim().split('\n');
        const responseJson = lines.find(line => line.startsWith('{'));
        if (responseJson) {
          const response = JSON.parse(responseJson);
          resolve(response);
        } else {
          reject(new Error('No valid JSON response found'));
        }
      } catch (error) {
        reject(error);
      }
    });
    
    mcp.stdin.write(JSON.stringify(request) + '\n');
    mcp.stdin.end();
  });
}

// Test the integrated dashboard tools
async function testDashboardIntegration() {
  try {
    console.log('1️⃣ Testing dashboard status...');
    const statusResponse = await sendMCPRequest('tools/call', {
      name: 'get_dashboard_status',
      arguments: {}
    });
    console.log('Status:', statusResponse.result?.content?.[0]?.text || 'No response');
    
    console.log('\n2️⃣ Starting live dashboard...');
    const startResponse = await sendMCPRequest('tools/call', {
      name: 'start_live_dashboard',
      arguments: {}
    });
    console.log('Start result:', startResponse.result?.content?.[0]?.text || 'No response');
    
    // Wait a moment for server to start
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    console.log('\n3️⃣ Getting updated dashboard status...');
    const statusResponse2 = await sendMCPRequest('tools/call', {
      name: 'get_dashboard_status',
      arguments: {}
    });
    console.log('Updated status:', statusResponse2.result?.content?.[0]?.text || 'No response');
    
    console.log('\n4️⃣ Starting a dashboard scan...');
    const scanResponse = await sendMCPRequest('tools/call', {
      name: 'run_dashboard_scan',
      arguments: { url: 'https://httpbin.org' }
    });
    console.log('Scan result:', scanResponse.result?.content?.[0]?.text || 'No response');
    
    console.log('\n5️⃣ Stopping dashboard...');
    const stopResponse = await sendMCPRequest('tools/call', {
      name: 'stop_live_dashboard',
      arguments: {}
    });
    console.log('Stop result:', stopResponse.result?.content?.[0]?.text || 'No response');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

testDashboardIntegration().catch(console.error);
