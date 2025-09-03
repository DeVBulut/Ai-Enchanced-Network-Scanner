import { parseCSVLogs, analyzeLogsForDDoS, generateSummaryReport } from './analyzeLogs.js';
import {
    queryLLM,
    getDDoSExplanation,
    getAnomalyDetectionSuggestions,
    getSummaryAnalysis
} from './llmAssist.js';
import fs from 'fs';
import readline from 'readline';
import { CONFIG } from './config.js';
import { logger } from './logger.js';

function formatLLMResponse(title, response) {
    // Normalize whitespace and add clear section headers
    const clean = (response || '').trim().replace(/\r?\n/g, '\n').replace(/\n{2,}/g, '\n\n');
    return `\n=== ${title} ===\n${clean}\n`;
}

class DDoSDetectionSystem {
    constructor() {
        this.analysisOutput = null;
        this.llmEnabled = true;
        this.rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
    }
    async runAnalysis(logFilePath, analysisOptions = {}) {
        console.log('Starting DDoS Detection Analysis...');
        try {
            const parsedLogEntries = await parseCSVLogs(logFilePath);
            if (parsedLogEntries.length === 0) {
                console.log('No log entries found in the file.');
                return;
            }
            this.analysisOutput = analyzeLogsForDDoS(parsedLogEntries);
            const summaryReport = generateSummaryReport(this.analysisOutput);
            console.log(summaryReport);
            if (this.llmEnabled && analysisOptions.useLLM !== false && this.analysisOutput.flaggedEntries.length > 0) {
                await this.promptForLLMAnalysis(analysisOptions);
            }
            if (analysisOptions.saveResults !== false) {
                await this.saveResults(analysisOptions.outputFile);
            }
            console.log('Analysis complete!');
        } catch (error) {
            console.error('Error during analysis:', error.message);
            throw error;
        }
    }
    async promptForLLMAnalysis(analysisOptions = {}) {
        const { flaggedEntries } = this.analysisOutput;
        const flaggedCount = flaggedEntries.length;
        console.log(`Found ${flaggedCount} suspicious entries.`);
        console.log('Would you like to perform LLM analysis on the top entries? (y/n): ');
        return new Promise((resolve) => {
            this.rl.question('', async (answer) => {
                const shouldAnalyze = answer.toLowerCase().startsWith('y');
                if (shouldAnalyze) {
                    await this.performLLMAnalysis(analysisOptions);
                } else {
                    console.log('Skipping LLM analysis.');
                }
                resolve();
            });
        });
    }
    async performLLMAnalysis(analysisOptions = {}, startIndex = 0) {
        if (!this.analysisOutput || this.analysisOutput.flaggedEntries.length === 0) {
            console.log('No suspicious entries found for LLM analysis.');
            return;
        }
        const { flaggedEntries } = this.analysisOutput;
        const batchSize = analysisOptions.maxLLMAnalysis || CONFIG.DEFAULT_MAX_LLM_ANALYSIS;
        const endIndex = Math.min(startIndex + batchSize, flaggedEntries.length);
        const entriesToAnalyze = flaggedEntries.slice(startIndex, endIndex);
        if (entriesToAnalyze.length === 0) {
            console.log('No more suspicious entries to analyze.');
            return;
        }
        console.log(`Analyzing suspicious entries ${startIndex + 1}-${endIndex} of ${flaggedEntries.length}...`);
        for (let i = 0; i < entriesToAnalyze.length; i++) {
            const flaggedEntry = entriesToAnalyze[i];
            // Only log the entry header and risk score, not every detail
            console.log(`Entry ${startIndex + i + 1}/${flaggedEntries.length}: IP ${flaggedEntry.sourceIP} (Risk Score: ${flaggedEntry.riskScore})`);
            try {
                const explanation = await getDDoSExplanation(flaggedEntry);
                console.log(formatLLMResponse('AI Analysis', explanation));
                const suggestions = await getAnomalyDetectionSuggestions(flaggedEntry);
                console.log(formatLLMResponse('AI Suggestions', suggestions));
            } catch (error) {
                console.error(`Error analyzing entry ${startIndex + i + 1}:`, error.message);
            }
        }
        if (entriesToAnalyze.length > 1) {
            try {
                const summaryAnalysis = await getSummaryAnalysis(entriesToAnalyze);
                console.log(formatLLMResponse('AI Batch Assessment', summaryAnalysis));
            } catch (error) {
                console.error('Error getting summary analysis:', error.message);
            }
        }
        if (endIndex < flaggedEntries.length) {
            return new Promise((resolve) => {
                this.rl.question(`Analyze the next ${Math.min(batchSize, flaggedEntries.length - endIndex)} suspicious entries? (y/n): `, async (answer) => {
                    const shouldContinue = answer.toLowerCase().startsWith('y');
                    if (shouldContinue) {
                        await this.performLLMAnalysis(analysisOptions, endIndex);
                    } else {
                        console.log('Stopped further LLM analysis.');
                    }
                    resolve();
                });
            });
        }
    }
    async saveResults(outputFile = CONFIG.DEFAULT_OUTPUT_FILE) {
        if (!this.analysisOutput) {
            console.log('No analysis results to save.');
            return;
        }
        try {
            const resultsToSave = {
                timestamp: new Date().toISOString(),
                summary: generateSummaryReport(this.analysisOutput),
                analysisResults: this.analysisOutput,
                config: {
                    highFrequencyThreshold: CONFIG.HIGH_FREQUENCY_THRESHOLD,
                    mediumFrequencyThreshold: CONFIG.MEDIUM_FREQUENCY_THRESHOLD,
                    analysisWindow: CONFIG.ANALYSIS_WINDOW
                }
            };
            fs.writeFileSync(outputFile, JSON.stringify(resultsToSave, null, 2));
            console.log(`Results saved to: ${outputFile}`);
        } catch (error) {
            console.error('Error saving results:', error.message);
        }
    }
    async testLLMConnection() {
        try {
            const testPrompt = 'Hello! Please respond with "LLM connection successful" if you can see this message.';
            const response = await queryLLM(testPrompt);
            if (response.includes('Error:')) {
                console.log('LLM connection failed:', response);
                return false;
            } else {
                console.log('LLM connection successful!');
                return true;
            }
        } catch (error) {
            console.error('LLM connection error:', error.message);
            return false;
        }
    }
    close() {
        if (this.rl) {
            this.rl.close();
        }
    }
    generateSampleData(outputFile = CONFIG.DEFAULT_SAMPLE_FILE, numEntries = CONFIG.DEFAULT_SAMPLE_ENTRIES) {
        let csvContent = ' Timestamp, Source IP, Destination IP, Total Fwd Packets, Flow Duration, Total Length of Fwd Packets, Label\n';
        const suspiciousIPs = ['192.168.1.100', '10.0.0.50', '172.16.0.25'];
        const normalIPs = ['203.0.113.1', '198.51.100.2', '192.0.2.3'];
        const suspiciousLabels = ['DrDoS_DNS', 'DrDoS_LDAP', 'WebDDoS', 'Syn', 'UDP-lag'];
        const normalLabels = ['BENIGN', 'Normal', 'Legitimate'];
        
        for (let i = 0; i < numEntries; i++) {
            const timestamp = new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000).toISOString();
            const isSuspicious = Math.random() < 0.3;
            const sourceIP = isSuspicious ?
                suspiciousIPs[Math.floor(Math.random() * suspiciousIPs.length)] :
                normalIPs[Math.floor(Math.random() * normalIPs.length)];
            const destinationIP = '192.168.1.1';
            const totalFwdPackets = isSuspicious ?
                Math.floor(Math.random() * 50) + 50 :
                Math.floor(Math.random() * 10) + 1;
            const flowDuration = Math.random() * 2;
            const totalLength = Math.floor(Math.random() * 10000) + 100;
            const label = isSuspicious ?
                suspiciousLabels[Math.floor(Math.random() * suspiciousLabels.length)] :
                normalLabels[Math.floor(Math.random() * normalLabels.length)];
            
            csvContent += `${timestamp},${sourceIP},${destinationIP},${totalFwdPackets},${flowDuration.toFixed(3)},${totalLength},${label}\n`;
        }
        
        // Add edge cases and malformed rows
        csvContent += `,MISSING_IP,10.0.0.1,5,0.150,1024,BENIGN\n`;
        csvContent += `2024-01-15T10:30:00Z,,10.0.0.1,5,0.150,1024,BENIGN\n`;
        csvContent += `2024-01-15T10:30:00Z,192.168.1.100,,5,0.150,1024,BENIGN\n`;
        csvContent += `2024-01-15T10:30:00Z,999.999.999.999,10.0.0.1,5,0.150,1024,BENIGN\n`;
        csvContent += `2024-01-15T10:30:00Z,192.168.1.100,10.0.0.1,-10,0.150,1024,BENIGN\n`;
        csvContent += `2024-01-15T10:30:00Z,192.168.1.100,10.0.0.1,0,0.150,1024,BENIGN\n`;
        csvContent += `2024-01-15T10:30:00Z,192.168.1.100,10.0.0.1,5,0.150,notanumber,BENIGN\n`;
        csvContent += `2024-01-15T10:30:00Z,192.168.1.100,10.0.0.1,5,notanumber,1024,BENIGN\n`;
        
        fs.writeFileSync(outputFile, csvContent);
        console.log(`Sample data generated: ${outputFile}`);
    }
}

export default DDoSDetectionSystem; 