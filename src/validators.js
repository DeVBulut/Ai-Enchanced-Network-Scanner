// Input validation utilities
import { logger } from './logger.js';

export function validateFilePath(filePath) {
    if (!filePath || typeof filePath !== 'string') {
        throw new Error('File path is required and must be a string');
    }
    
    if (!filePath.trim()) {
        throw new Error('File path cannot be empty');
    }
    
    return filePath.trim();
}

export function validatePositiveInteger(value, fieldName) {
    const num = parseInt(value);
    if (isNaN(num) || num <= 0 || !Number.isInteger(num)) {
        throw new Error(`${fieldName} must be a positive integer, got: ${value}`);
    }
    return num;
}

export function validateIPAddress(ip) {
    if (!ip || typeof ip !== 'string') {
        return false;
    }
    
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip.trim());
}

export function validateTimestamp(timestamp) {
    if (!timestamp || typeof timestamp !== 'string') {
        return false;
    }
    
    const date = new Date(timestamp);
    return !isNaN(date.getTime()) && date.getTime() > 0;
}

export function sanitizeCSVData(data) {
    const sanitized = {};
    
    for (const [key, value] of Object.entries(data)) {
        if (typeof value === 'string') {
            sanitized[key] = value.trim();
        } else {
            sanitized[key] = value;
        }
    }
    
    return sanitized;
}

export function validateAnalysisOptions(options) {
    const validated = {
        useLLM: Boolean(options.useLLM),
        saveResults: Boolean(options.saveResults),
        maxLLMAnalysis: validatePositiveInteger(
            options.maxLLMAnalysis || 3, 
            'maxLLMAnalysis'
        ),
        outputFile: options.outputFile ? validateFilePath(options.outputFile) : undefined
    };
    
    return validated;
}
