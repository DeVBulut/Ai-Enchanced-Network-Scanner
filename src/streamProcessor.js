// Streaming CSV processor for large files
import fs from 'fs';
import csv from 'csv-parser';
import { EventEmitter } from 'events';
import { logger } from './logger.js';
import { CONFIG } from './config.js';

export class StreamingCSVProcessor extends EventEmitter {
    constructor(filePath, options = {}) {
        super();
        this.filePath = filePath;
        this.batchSize = options.batchSize || 1000;
        this.currentBatch = [];
        this.totalProcessed = 0;
        this.isProcessing = false;
    }

    async process() {
        return new Promise((resolve, reject) => {
            if (this.isProcessing) {
                reject(new Error('Processor is already running'));
                return;
            }

            this.isProcessing = true;
            let rowNumber = 1;

            const stream = fs.createReadStream(this.filePath)
                .pipe(csv())
                .on('data', (data) => {
                    try {
                        const normalizedEntry = this.normalizeLogEntry(data, rowNumber);
                        if (normalizedEntry) {
                            this.currentBatch.push(normalizedEntry);
                            
                            if (this.currentBatch.length >= this.batchSize) {
                                this.emit('batch', this.currentBatch);
                                this.totalProcessed += this.currentBatch.length;
                                this.currentBatch = [];
                            }
                        }
                    } catch (error) {
                        logger.warn(`Error processing row ${rowNumber}:`, error.message);
                    }
                    rowNumber++;
                })
                .on('end', () => {
                    // Process remaining entries
                    if (this.currentBatch.length > 0) {
                        this.emit('batch', this.currentBatch);
                        this.totalProcessed += this.currentBatch.length;
                    }
                    
                    this.emit('complete', { totalProcessed: this.totalProcessed });
                    resolve({ totalProcessed: this.totalProcessed });
                })
                .on('error', (error) => {
                    this.isProcessing = false;
                    reject(error);
                });
        });
    }

    normalizeLogEntry(data, rowNumber) {
        const normalized = {
            timestamp: data[CONFIG.CSV_COLUMNS.TIMESTAMP]?.trim() || 'N/A',
            sourceIP: data[CONFIG.CSV_COLUMNS.SOURCE_IP]?.trim() || 'UNKNOWN',
            destinationIP: data[CONFIG.CSV_COLUMNS.DEST_IP]?.trim() || 'UNKNOWN',
            requestCount: parseInt(data[CONFIG.CSV_COLUMNS.FWD_PACKETS]) || 1,
            duration: parseFloat(data[CONFIG.CSV_COLUMNS.FLOW_DURATION]) || 0,
            bytes: parseFloat(data[CONFIG.CSV_COLUMNS.TOTAL_LENGTH]) || 0,
            label: data[CONFIG.CSV_COLUMNS.LABEL]?.trim() || 'N/A',
            userAgent: 'N/A',
            responseCode: 'N/A',
            method: 'N/A',
            path: 'N/A'
        };

        // Validate required fields
        if (normalized.timestamp === 'N/A' || 
            normalized.sourceIP === 'UNKNOWN' || 
            normalized.destinationIP === 'UNKNOWN') {
            logger.warn(`Skipping malformed row ${rowNumber} (missing required fields)`);
            return null;
        }

        return normalized;
    }

    stop() {
        this.isProcessing = false;
        this.removeAllListeners();
    }
}
