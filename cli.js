#!/usr/bin/env node

import fs from 'fs';
import { encryptText, encryptFile } from './index.js';

// Help message
function showHelp() {
    console.log('Usage:');
    console.log("  Encrypt text: $ npx encrypt 'Your plain text here'");
    console.log('  Encrypt file: $ npx encrypt plain_text.txt');
}

// Main execution
const arg = process.argv[2];

if (!arg || arg === '--help' || arg === '-h') {
    showHelp();
    process.exit(arg ? 0 : 1);
}

// Check if input is a file or plain text
if (fs.existsSync(arg)) {
    encryptFile(arg);
} else {
    encryptText(arg);
}
