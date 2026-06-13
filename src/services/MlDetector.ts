// src/services/MlDetector.ts - FIXED: NEVER RETURNS NULL
import * as fs from 'fs';
import * as path from 'path';
import { Logger } from '../utils/Logger';

interface FeatureVector {
  latency: number;
  ttl: number;
  openPorts: number;
  hasProxyHeaders: boolean;
  hasPtrRecord: boolean;
  hasMxRecord: boolean;
  reverseDnsLength: number;
  reverseDnsEntropy: number;
  ispLength: number;
  orgLength: number;
  ispHasVpnKeyword: boolean;
  ispHasHostingKeyword: boolean;
  ispHasProxyKeyword: boolean;
  asnNumber: number;
  prefixCount: number;
  ipChanges24h: number;
  countryChanges24h: number;
  avgSessionDuration: number;
  tlsVersion: number;
  cipherStrength: number;
  certValidityDays: number;
  abuseScore: number;
  torExitNode: boolean;
  knownVpnRange: boolean;
  isDatacenterRange: boolean;
}

interface TrainingSample {
  features: FeatureVector;
  label: number;
  weight: number;
}

interface ModelWeights {
  [key: string]: number;
}

interface PredictionResult {
  score: number;
  confidence: number;
  isVpn: boolean;
  isProxy: boolean;
  isTor: boolean;
  isHosting: boolean;
  isDatacenter: boolean;
  featureImportance: { feature: string; importance: number }[];
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
}

export class MlDetector {
  private static instance: MlDetector;
  private logger: Logger;
  private weights: ModelWeights;
  private trainingData: TrainingSample[];
  private modelPath: string;
  private dataPath: string;
  private isInitialized: boolean = false;
  private readonly LEARNING_RATE = 0.01;
  private readonly EPOCHS = 100;

  private featureStats: {
    [key: string]: { mean: number; std: number; min: number; max: number };
  } = {};

  private constructor() {
    this.logger = Logger.getInstance();
    this.modelPath = path.join(process.cwd(), 'data', 'ml_model.json');
    this.dataPath = path.join(process.cwd(), 'data', 'ml_training_data.json');
    this.weights = {};
    this.trainingData = [];
    
    this.initializeModel();
  }

  static getInstance(): MlDetector {
    if (!MlDetector.instance) {
      MlDetector.instance = new MlDetector();
    }
    return MlDetector.instance;
  }

  private initializeModel(): void {
    this.weights = {
      latency_weight: 0.01, ttl_weight: 0.01, openPorts_weight: 0.01, proxyHeaders_weight: 0.01,
      ptrRecord_weight: 0.01, mxRecord_weight: 0.01, reverseDnsLength_weight: 0.01, reverseDnsEntropy_weight: 0.01,
      ispLength_weight: 0.01, orgLength_weight: 0.01, ispVpnKeyword_weight: 0.01, ispHostingKeyword_weight: 0.01, ispProxyKeyword_weight: 0.01,
      asnNumber_weight: 0.01, prefixCount_weight: 0.01,
      ipChanges_weight: 0.01, countryChanges_weight: 0.01, sessionDuration_weight: 0.01,
      tlsVersion_weight: 0.01, cipherStrength_weight: 0.01, certValidity_weight: 0.01,
      abuseScore_weight: 0.01, torExit_weight: 0.01, knownVpnRange_weight: 0.01, datacenterRange_weight: 0.01,
      bias: 0
    };

    this.loadModel();
    this.loadTrainingData();
    
    if (this.trainingData.length >= 50) {
      try { this.train(); } catch (e) { this.logger.error('Initial training failed', e); }
    }
    
    this.isInitialized = true;
    this.logger.info(`ML Detector initialized with ${this.trainingData.length} samples`);
  }

  private loadModel(): void {
    try {
      if (fs.existsSync(this.modelPath)) {
        const data = JSON.parse(fs.readFileSync(this.modelPath, 'utf-8'));
        if (data.weights) this.weights = { ...this.weights, ...data.weights };
        if (data.featureStats) this.featureStats = data.featureStats;
      }
    } catch (error) {
      this.logger.warn('Failed to load ML model, using defaults');
    }
  }

  private saveModel(): void {
    try {
      const dir = path.dirname(this.modelPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(this.modelPath, JSON.stringify({
        weights: this.weights, featureStats: this.featureStats,
        trainedAt: new Date().toISOString(), samples: this.trainingData.length
      }, null, 2));
    } catch (error) {
      this.logger.error('Failed to save ML model');
    }
  }

  private loadTrainingData(): void {
    try {
      if (fs.existsSync(this.dataPath)) {
        this.trainingData = JSON.parse(fs.readFileSync(this.dataPath, 'utf-8'));
      }
    } catch (error) {
      this.logger.warn('Failed to load training data');
    }
  }

  private saveTrainingData(): void {
    try {
      const dir = path.dirname(this.dataPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(this.dataPath, JSON.stringify(this.trainingData.slice(-10000), null, 2));
    } catch (error) {
      this.logger.error('Failed to save training data');
    }
  }

  extractFeatures(data: {
    ip: string;
    latency?: number; ttl?: number; openPorts?: number[]; hasProxyHeaders?: boolean;
    hasPtrRecord?: boolean; hasMxRecord?: boolean; reverseDns?: string;
    isp?: string; org?: string; asn?: string; prefixCount?: number;
    tlsVersion?: string; cipherStrength?: number; certValidityDays?: number;
    abuseScore?: number; isTorExit?: boolean; knownVpnRange?: boolean; isDatacenterRange?: boolean;
    ipChanges24h?: number; countryChanges24h?: number; avgSessionDuration?: number;
  }): FeatureVector {
    return {
      latency: data.latency || 0,
      ttl: data.ttl || 64,
      openPorts: data.openPorts?.length || 0,
      hasProxyHeaders: data.hasProxyHeaders || false,
      hasPtrRecord: data.hasPtrRecord || false,
      hasMxRecord: data.hasMxRecord || false,
      reverseDnsLength: data.reverseDns?.length || 0,
      reverseDnsEntropy: this.calculateEntropy(data.reverseDns || ''),
      ispLength: data.isp?.length || 0,
      orgLength: data.org?.length || 0,
      ispHasVpnKeyword: this.containsVpnKeyword(data.isp || ''),
      ispHasHostingKeyword: this.containsHostingKeyword(data.isp || ''),
      ispHasProxyKeyword: this.containsProxyKeyword(data.isp || ''),
      asnNumber: parseInt((data.asn || '').replace(/\D/g, '') || '0'),
      prefixCount: data.prefixCount || 0,
      ipChanges24h: data.ipChanges24h || 0,
      countryChanges24h: data.countryChanges24h || 0,
      avgSessionDuration: data.avgSessionDuration || 0,
      tlsVersion: this.parseTlsVersion(data.tlsVersion || ''),
      cipherStrength: data.cipherStrength || 0,
      certValidityDays: data.certValidityDays || 0,
      abuseScore: data.abuseScore || 0,
      torExitNode: data.isTorExit || false,
      knownVpnRange: data.knownVpnRange || false,
      isDatacenterRange: data.isDatacenterRange || false,
    };
  }

  predict(features: FeatureVector): PredictionResult {
    if (!this.isInitialized) {
      return this.getDefaultPrediction();
    }

    try {
      const normalizedFeatures = this.normalizeFeatures(features);
      
      let score = this.weights.bias || 0;
      
      score += normalizedFeatures.latency * (this.weights.latency_weight || 0);
      score += normalizedFeatures.ttl * (this.weights.ttl_weight || 0);
      score += normalizedFeatures.openPorts * (this.weights.openPorts_weight || 0);
      score += (normalizedFeatures.hasProxyHeaders ? 1 : 0) * (this.weights.proxyHeaders_weight || 0);
      score += (normalizedFeatures.hasPtrRecord ? 1 : 0) * (this.weights.ptrRecord_weight || 0);
      score += (normalizedFeatures.hasMxRecord ? 1 : 0) * (this.weights.mxRecord_weight || 0);
      score += normalizedFeatures.reverseDnsLength * (this.weights.reverseDnsLength_weight || 0);
      score += normalizedFeatures.reverseDnsEntropy * (this.weights.reverseDnsEntropy_weight || 0);
      score += normalizedFeatures.ispLength * (this.weights.ispLength_weight || 0);
      score += normalizedFeatures.orgLength * (this.weights.orgLength_weight || 0);
      score += (normalizedFeatures.ispHasVpnKeyword ? 1 : 0) * (this.weights.ispVpnKeyword_weight || 0);
      score += (normalizedFeatures.ispHasHostingKeyword ? 1 : 0) * (this.weights.ispHostingKeyword_weight || 0);
      score += (normalizedFeatures.ispHasProxyKeyword ? 1 : 0) * (this.weights.ispProxyKeyword_weight || 0);
      score += normalizedFeatures.asnNumber * (this.weights.asnNumber_weight || 0);
      score += normalizedFeatures.prefixCount * (this.weights.prefixCount_weight || 0);
      score += normalizedFeatures.ipChanges24h * (this.weights.ipChanges_weight || 0);
      score += normalizedFeatures.countryChanges24h * (this.weights.countryChanges_weight || 0);
      score += normalizedFeatures.avgSessionDuration * (this.weights.sessionDuration_weight || 0);
      score += normalizedFeatures.tlsVersion * (this.weights.tlsVersion_weight || 0);
      score += normalizedFeatures.cipherStrength * (this.weights.cipherStrength_weight || 0);
      score += normalizedFeatures.certValidityDays * (this.weights.certValidity_weight || 0);
      score += normalizedFeatures.abuseScore * (this.weights.abuseScore_weight || 0);
      score += (normalizedFeatures.torExitNode ? 1 : 0) * (this.weights.torExit_weight || 0);
      score += (normalizedFeatures.knownVpnRange ? 1 : 0) * (this.weights.knownVpnRange_weight || 0);
      score += (normalizedFeatures.isDatacenterRange ? 1 : 0) * (this.weights.datacenterRange_weight || 0);

      const probability = this.sigmoid(score);
      const confidence = Math.min(0.95, Math.abs(probability - 0.5) * 2);
      const featureImportance = this.calculateFeatureImportance(normalizedFeatures);

      const isVpn = probability > 0.7 && (normalizedFeatures.ispHasVpnKeyword || normalizedFeatures.knownVpnRange);
      const isProxy = probability > 0.6 && (normalizedFeatures.openPorts > 2 || normalizedFeatures.hasProxyHeaders);
      const isTor = probability > 0.9 && normalizedFeatures.torExitNode;
      const isHosting = probability > 0.5 && (normalizedFeatures.ispHasHostingKeyword || normalizedFeatures.isDatacenterRange);
      const isDatacenter = probability > 0.5 && normalizedFeatures.isDatacenterRange;

      let threatLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
      if (probability > 0.9) threatLevel = 'critical';
      else if (probability > 0.7) threatLevel = 'high';
      else if (probability > 0.4) threatLevel = 'medium';

      return {
        score: Math.round(probability * 100),
        confidence: Math.round(confidence * 100) / 100,
        isVpn, isProxy, isTor, isHosting, isDatacenter,
        featureImportance, threatLevel
      };
    } catch (error) {
      this.logger.error('ML prediction failed', error);
      return this.getDefaultPrediction();
    }
  }

  addTrainingSample(features: FeatureVector, label: number, weight: number = 1): void {
    this.trainingData.push({ features, label, weight });
    if (this.trainingData.length > 10000) {
      this.trainingData = this.trainingData.slice(-10000);
    }
    if (this.trainingData.length % 100 === 0) {
      try { this.train(); } catch (e) {}
      try { this.saveTrainingData(); } catch (e) {}
    }
  }

  private train(): void {
    if (this.trainingData.length < 10) return;

    this.updateFeatureStats();
    const normalizedData = this.trainingData.map(sample => ({
      features: this.normalizeFeatures(sample.features),
      label: sample.label,
      weight: sample.weight
    }));

    for (let epoch = 0; epoch < this.EPOCHS; epoch++) {
      let totalLoss = 0;
      const shuffled = [...normalizedData].sort(() => Math.random() - 0.5);
      
      for (const sample of shuffled) {
        const prediction = this.predictRaw(sample.features);
        const error = sample.label - prediction;
        const gradient = error * this.sigmoidDerivative(prediction);
        
        const l2Lambda = 0.001;
        for (const key of Object.keys(this.weights)) {
          if (key === 'bias') {
            this.weights[key] += this.LEARNING_RATE * gradient * sample.weight;
          } else {
            const featureKey = key.replace('_weight', '');
            const featureValue = (sample.features as any)[featureKey] || 0;
            this.weights[key] += this.LEARNING_RATE * (gradient * featureValue * sample.weight - l2Lambda * this.weights[key]);
          }
        }
        totalLoss += error * error;
      }
      
      if (totalLoss / shuffled.length < 0.001) break;
    }
    
    this.saveModel();
  }

  private predictRaw(features: FeatureVector): number {
    let score = this.weights.bias || 0;
    for (const [key, value] of Object.entries(features)) {
      const weightKey = `${key}_weight`;
      if (this.weights[weightKey] !== undefined) {
        score += (typeof value === 'boolean' ? (value ? 1 : 0) : value) * (this.weights[weightKey] || 0);
      }
    }
    return this.sigmoid(score);
  }

  private normalizeFeatures(features: FeatureVector): FeatureVector {
    const normalized: any = {};
    for (const [key, value] of Object.entries(features)) {
      if (typeof value === 'boolean') {
        normalized[key] = value;
      } else if (typeof value === 'number') {
        const stats = this.featureStats[key];
        if (stats && stats.std > 0) {
          normalized[key] = (value - stats.mean) / stats.std;
        } else {
          normalized[key] = value;
        }
      } else {
        normalized[key] = value;
      }
    }
    return normalized as FeatureVector;
  }

  private updateFeatureStats(): void {
    const numericFeatures = [
      'latency', 'ttl', 'openPorts', 'reverseDnsLength', 'reverseDnsEntropy',
      'ispLength', 'orgLength', 'asnNumber', 'prefixCount',
      'ipChanges24h', 'countryChanges24h', 'avgSessionDuration',
      'tlsVersion', 'cipherStrength', 'certValidityDays', 'abuseScore'
    ];
    
    for (const feature of numericFeatures) {
      const values = this.trainingData.map(s => (s.features as any)[feature]).filter((v: any) => typeof v === 'number');
      if (values.length > 0) {
        const mean = values.reduce((a: number, b: number) => a + b, 0) / values.length;
        const variance = values.reduce((a: number, b: number) => a + (b - mean) ** 2, 0) / values.length;
        const std = Math.sqrt(variance);
        this.featureStats[feature] = { mean, std: std || 1, min: Math.min(...values), max: Math.max(...values) };
      }
    }
  }

  private calculateFeatureImportance(features: FeatureVector): { feature: string; importance: number }[] {
    const importances: { feature: string; importance: number }[] = [];
    for (const [key, value] of Object.entries(features)) {
      const weightKey = `${key}_weight`;
      if (this.weights[weightKey] !== undefined) {
        const contribution = Math.abs((typeof value === 'boolean' ? (value ? 1 : 0) : value) * (this.weights[weightKey] || 0));
        importances.push({ feature: key, importance: contribution });
      }
    }
    return importances.sort((a, b) => b.importance - a.importance).slice(0, 10);
  }

  private sigmoid(x: number): number { return 1 / (1 + Math.exp(-x)); }
  private sigmoidDerivative(x: number): number { return x * (1 - x); }

  private calculateEntropy(str: string): number {
    if (!str) return 0;
    const frequencies: { [key: string]: number } = {};
    for (const char of str) frequencies[char] = (frequencies[char] || 0) + 1;
    let entropy = 0;
    const len = str.length;
    for (const freq of Object.values(frequencies)) { const p = freq / len; entropy -= p * Math.log2(p); }
    return entropy;
  }

  private parseTlsVersion(version: string): number {
    const versions: { [key: string]: number } = { 'TLSv1': 1, 'TLSv1.1': 1.1, 'TLSv1.2': 1.2, 'TLSv1.3': 1.3, 'SSLv3': 0.3 };
    return versions[version] || 0;
  }

  private containsVpnKeyword(str: string): boolean {
    const keywords = ['vpn', 'nord', 'express', 'surfshark', 'cyberghost', 'proton', 'mullvad', 'windscribe', 'hidemyass', 'tunnelbear', 'hotspot', 'ipvanish', 'purevpn', 'privatevpn', 'trustzone', 'airvpn', 'ivpn', 'ovpn', 'strongvpn', 'torguard'];
    const lower = str.toLowerCase();
    return keywords.some(k => lower.includes(k));
  }

  private containsHostingKeyword(str: string): boolean {
    const keywords = ['hosting', 'server', 'cloud', 'vps', 'vds', 'dedicated', 'datacenter', 'colo', 'digitalocean', 'linode', 'vultr', 'ovh', 'hetzner', 'aws', 'azure', 'gcp'];
    const lower = str.toLowerCase();
    return keywords.some(k => lower.includes(k));
  }

  private containsProxyKeyword(str: string): boolean {
    const keywords = ['proxy', 'proxies', 'socks', 'shadowsocks', 'v2ray', 'trojan', 'xray', 'vmess', 'vless', 'hysteria', 'brightdata', 'luminati', 'oxylabs', 'smartproxy', 'geosurf', 'netnut'];
    const lower = str.toLowerCase();
    return keywords.some(k => lower.includes(k));
  }

  private getDefaultPrediction(): PredictionResult {
    return {
      score: 0, confidence: 0, isVpn: false, isProxy: false, isTor: false, isHosting: false, isDatacenter: false,
      featureImportance: [], threatLevel: 'low'
    };
  }

  getStats(): { samples: number; accuracy: number; features: number; lastTrained: string } {
    let accuracy = 0;
    if (this.trainingData.length > 0) {
      let correct = 0;
      const testSamples = this.trainingData.slice(-100);
      for (const sample of testSamples) {
        const prediction = this.predict(sample.features);
        const predictedLabel = prediction.score > 50 ? 1 : 0;
        if (predictedLabel === sample.label) correct++;
      }
      accuracy = correct / testSamples.length;
    }
    return { samples: this.trainingData.length, accuracy: Math.round(accuracy * 100) / 100, features: Object.keys(this.weights).length - 1, lastTrained: new Date().toISOString() };
  }

  exportModel(): object {
    return { weights: this.weights, featureStats: this.featureStats, samples: this.trainingData.length, accuracy: this.getStats().accuracy };
  }

  reset(): void {
    this.weights = {}; this.featureStats = {}; this.trainingData = [];
    this.initializeModel(); this.saveModel(); this.saveTrainingData();
    this.logger.info('ML model reset to initial state');
  }
}