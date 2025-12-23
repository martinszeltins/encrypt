import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import argon2 from 'argon2';

const ALGORITHM = 'aes-256-gcm';
const SALT_LENGTH = 16;
const KEY_LENGTH = 32;
const NONCE_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

// Function to get password from user
function getPassword() {
    return new Promise((resolve) => {
        const stdin = process.stdin;
        
        stdin.resume();
        stdin.setEncoding('utf8');

        let password = '';
        process.stdout.write('enter aes-256-gcm encryption password: ');

        if (stdin.isTTY) {
            // TTY mode - hide password input and read character by character
            stdin.setRawMode(true);
            
            const onData = (char) => {
                const charStr = char.toString('utf8');
                
                if (charStr === '\n' || charStr === '\r' || charStr === '\u0004') {
                    stdin.setRawMode(false);
                    stdin.removeListener('data', onData);
                    stdin.pause();
                    process.stdout.write('\n');
                    resolve(password);
                } else if (charStr === '\u0003') {
                    // Ctrl+C
                    process.exit(1);
                } else if (charStr === '\u007f' || charStr === '\b') {
                    // Backspace
                    if (password.length > 0) {
                        password = password.slice(0, -1);
                    }
                } else {
                    password += charStr;
                }
            };
            
            stdin.on('data', onData);
        } else {
            // Non-TTY mode - read entire line (for piped input)
            const onData = (data) => {
                password += data;
                if (password.includes('\n')) {
                    password = password.split('\n')[0];
                    stdin.removeListener('data', onData);
                    stdin.pause();
                    resolve(password);
                }
            };
            
            stdin.on('data', onData);
        }
    });
}

// Derive key from password using Argon2id (memory-hard, GPU-resistant)
// Note: For GCM, we don't derive the nonce - it must be random
async function deriveKey(password, salt) {
    const hash = await argon2.hash(password, {
        type: argon2.argon2id,
        salt: salt,
        saltLength: SALT_LENGTH,
        hashLength: KEY_LENGTH,
        timeCost: 3,        // iterations
        memoryCost: 65536,  // 64 MB (memory-hard)
        parallelism: 4,     // threads
        raw: true           // return raw bytes, not encoded
    });
    return hash;
}

// Function to encrypt text and output base64
async function encryptText(plainText) {
    try {
        const password = await getPassword();
        const salt = crypto.randomBytes(SALT_LENGTH);
        const nonce = crypto.randomBytes(NONCE_LENGTH);
        const key = await deriveKey(password, salt);

        const cipher = crypto.createCipheriv(ALGORITHM, key, nonce);
        
        // Add AAD (Additional Authenticated Data) - timestamp for text
        const aad = Buffer.from(`text:${Date.now()}`, 'utf8');
        cipher.setAAD(aad);
        
        // Encrypt the data
        const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
        const authTag = cipher.getAuthTag();
        
        // Format: aadLength(2) + salt(16) + nonce(12) + authTag(16) + aad + encrypted data
        const aadLength = Buffer.allocUnsafe(2);
        aadLength.writeUInt16BE(aad.length);
        
        const result = Buffer.concat([
            aadLength,
            salt,
            nonce,
            authTag,
            aad,
            encrypted
        ]);

        console.log('');
        process.stdout.write(result.toString('base64'));
        console.log('');
        console.log('');
    } catch (error) {
        console.error('Encryption failed:', error.message);
        process.exit(1);
    }
}

// Function to encrypt a file and output the path of the encrypted file
async function encryptFile(inputFile) {
    try {
        const password = await getPassword();
        const outputFile = `${inputFile}.enc`;
        const salt = crypto.randomBytes(SALT_LENGTH);
        const nonce = crypto.randomBytes(NONCE_LENGTH);
        const key = await deriveKey(password, salt);

        const cipher = crypto.createCipheriv(ALGORITHM, key, nonce);
        
        // Add AAD (Additional Authenticated Data) - original filename
        const filename = path.basename(inputFile);
        const aad = Buffer.from(`file:${filename}`, 'utf8');
        cipher.setAAD(aad);
        
        // Read entire file for GCM (GCM needs auth tag after encryption)
        const inputData = fs.readFileSync(inputFile);
        const encrypted = Buffer.concat([cipher.update(inputData), cipher.final()]);
        const authTag = cipher.getAuthTag();
        
        // Format: aadLength(2) + salt(16) + nonce(12) + authTag(16) + aad + encrypted data
        const aadLength = Buffer.allocUnsafe(2);
        aadLength.writeUInt16BE(aad.length);
        
        const result = Buffer.concat([
            aadLength,
            salt,
            nonce,
            authTag,
            aad,
            encrypted
        ]);
        
        fs.writeFileSync(outputFile, result);
        
        console.log('');
        console.log(`👉 Encrypted file: ${path.resolve(outputFile)}`);
        console.log('');
    } catch (error) {
        console.error('Encryption failed:', error.message);
        process.exit(1);
    }
}

export { encryptText, encryptFile };
