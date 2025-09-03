// Centralized configuration for the DDoS Detection System
export const CONFIG = {
    // File paths
    DEFAULT_OUTPUT_FILE: 'ddos-analysis-results.json',
    DEFAULT_SAMPLE_FILE: 'sample-logs.csv',
    
    // Analysis settings
    DEFAULT_SAMPLE_ENTRIES: 100,
    DEFAULT_MAX_LLM_ANALYSIS: 3,
    ANALYSIS_WINDOW: 5,
    
    // Detection thresholds
    HIGH_FREQUENCY_THRESHOLD: 100,
    MEDIUM_FREQUENCY_THRESHOLD: 50,
    
    // LLM settings
    LLM_ENDPOINT: 'http://localhost:11434/api/generate',
    LLM_MODEL: 'mistral',
    LLM_TIMEOUT: 30000, // 30 seconds
    
    // CSV parsing
    CSV_COLUMNS: {
        TIMESTAMP: ' Timestamp',
        SOURCE_IP: ' Source IP',
        DEST_IP: ' Destination IP',
        FWD_PACKETS: ' Total Fwd Packets',
        FLOW_DURATION: ' Flow Duration',
        TOTAL_LENGTH: 'Total Length of Fwd Packets',
        LABEL: ' Label'
    },
    
    // Detection patterns
    SUSPICIOUS_USER_AGENTS: [
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python', 'java',
        'go-http-client', 'okhttp', 'requests', 'urllib', 'scrapy'
    ],
    
    SUSPICIOUS_IP_PATTERNS: [
        /^10\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./, /^192\.168\./,
        /^127\./, /^0\.0\.0\.0/, /^255\.255\.255\.255/
    ],
    
    SUSPICIOUS_RESPONSE_CODES: ['429', '503', '502', '504'],
    SUSPICIOUS_METHODS: ['HEAD', 'OPTIONS', 'TRACE', 'CONNECT'],
    
    KNOWN_DDOS_LABELS: [
        'DrDoS_DNS', 'DrDoS_LDAP', 'DrDoS_MSSQL', 'DrDoS_NetBIOS', 'DrDoS_NTP',
        'DrDoS_SNMP', 'DrDoS_SSDP', 'DrDoS_UDP', 'DrDoS_WebDDoS', 'Syn', 'TFTP',
        'UDP', 'UDP-lag', 'WebDDoS', 'LDAP', 'MSSQL', 'NetBIOS', 'NTP', 'SNMP', 'SSDP'
    ]
};
