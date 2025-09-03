import { parseCSVLogs, analyzeLogsForDDoS, generateSummaryReport } from './analyzeLogs.js';
import {
    queryLLM,
    getDDoSExplanation,
    getAnomalyDetectionSuggestions,
    getSummaryAnalysis
} from './llmAssist.js';
import fs from 'fs';
import path from 'path';
import readline from 'readline';
import DDoSDetectionSystem from './ddosDetectionSystem.js';
import { CONFIG } from './config.js';
import { logger } from './logger.js';

/**
 * Main execution function
 */
async function main() {
    const args = process.argv.slice(2);
    const system = new DDoSDetectionSystem();

    // Parse command line arguments
    const analysisOptions = {
        useLLM: true,
        saveResults: true,
        maxLLMAnalysis: CONFIG.DEFAULT_MAX_LLM_ANALYSIS
    };

    let logFilePath = null;

    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '--help':
            case '-h':
                showHelp();
                system.close();
                process.exit(0);
            case '--test-llm':
                await system.testLLMConnection();
                system.close();
                process.exit(0);
            case '--generate-sample': {
                let sampleFile = args[i + 1] || CONFIG.DEFAULT_SAMPLE_FILE;
                // Automatically add .csv if not present
                if (sampleFile && !sampleFile.toLowerCase().endsWith('.csv')) {
                    sampleFile += '.csv';
                }
                const numEntries = parseInt(args[i + 2]);
                if (isNaN(numEntries) || numEntries <= 0) {
                    console.error('Invalid number of entries for --generate-sample. Must be a positive integer.');
                    system.close();
                    process.exit(1);
                }
                system.generateSampleData(sampleFile, numEntries);
                system.close();
                process.exit(0);
            }
            case '--no-llm':
                analysisOptions.useLLM = false;
                break;
            case '--no-save':
                analysisOptions.saveResults = false;
                break;
            case '--max-llm': {
                const maxLLM = parseInt(args[i + 1]);
                if (isNaN(maxLLM) || maxLLM <= 0) {
                    console.error('Invalid value for --max-llm. Must be a positive integer.');
                    return;
                }
                analysisOptions.maxLLMAnalysis = maxLLM;
                i++;
                break;
            }
            case '--output':
                analysisOptions.outputFile = args[i + 1];
                i++;
                break;
            default:
                if (!logFilePath && !args[i].startsWith('--')) {
                    logFilePath = args[i];
                }
                break;
        }
    }

    if (!logFilePath) {
        console.error('Please provide a CSV log file path.');
        console.error('Usage: node app.js <log-file.csv> [options]');
        console.error('Use --help for more information.');
        system.close();
        process.exit(1);
    }

    // Check if file exists
    if (!fs.existsSync(logFilePath)) {
        console.error(`Log file not found: ${logFilePath}`);
        console.error('Use --generate-sample to create sample data for testing.');
        system.close();
        process.exit(1);
    }

    // Run the analysis
    try {
        await system.runAnalysis(logFilePath, analysisOptions);
    } catch (err) {
        console.error('Fatal error during analysis:', err.message);
        process.exit(1);
    } finally {
        system.close();
    }
}

/**
 * Show help information
 */
function showHelp() {
    console.log(`
DDoS Detection System

USAGE:
  node app.js <log-file.csv> [options]

PREREQUISITES:
  - Ollama running on localhost:11434
  - Mistral model installed in Ollama
  - Node.js with ES6 modules support

OPTIONS:
  --help, -h              Show this help message
  --test-llm              Test LLM connection
  --generate-sample       Generate sample CSV data for testing
  --no-llm                Disable LLM analysis
  --no-save               Don't save results to file
  --max-llm <number>      Maximum number of entries to analyze with LLM (default: 3)
  --output <file>         Output file for results (default: ddos-analysis-results.json)

EXAMPLES:
  node app.js logs.csv
  node app.js logs.csv --no-llm
  node app.js logs.csv --max-llm 5 --output results.json
  node app.js --generate-sample sample.csv 200
  node app.js --test-llm

CSV FORMAT:
  The system expects CSV files with columns like:
  timestamp,sourceIP,destinationIP,requestCount,userAgent,responseCode,method,path,bytes,duration

FEATURES:
  - Interactive LLM analysis (y/n)
  - Automatic suspicious entry detection
  - Risk scoring and prioritization
`);
}

// Run the main function if this file is executed directly
if (process.argv[1] && process.argv[1].endsWith('app.js')) {
    main().catch(console.error);
} 