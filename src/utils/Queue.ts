// src/utils/Queue.ts - OPTIMIZED VERSION (fixed substr deprecation)
import { QueueTask } from '../types';
import { Logger } from './Logger';

// Queue system for async task processing - singleton pattern
export class QueueSystem {
  private static instance: QueueSystem;
  private queue: QueueTask[];
  private processing: boolean;
  private logger: Logger;
  private taskHandlers: Map<string, (task: QueueTask) => Promise<void>>;

  private constructor() {
    this.queue = [];
    this.processing = false;
    this.logger = Logger.getInstance();
    this.taskHandlers = new Map();
  }

  static getInstance(): QueueSystem {
    if (!QueueSystem.instance) {
      QueueSystem.instance = new QueueSystem();
    }
    return QueueSystem.instance;
  }

  // Register handler for a specific task type
  registerHandler(type: string, handler: (task: QueueTask) => Promise<void>): void {
    this.taskHandlers.set(type, handler);
  }

  // Add task to queue with priority (lower number = higher priority)
  async addTask(task: Omit<QueueTask, 'id' | 'added_at' | 'retries'>): Promise<void> {
    const fullTask: QueueTask = {
      ...task,
      id: `${task.type}_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`,
      added_at: Date.now(),
      retries: 0,
      max_retries: task.max_retries || 3
    };

    // Insert with priority (lower number = higher priority)
    const insertIndex = this.queue.findIndex(t => t.priority > fullTask.priority);
    if (insertIndex === -1) {
      this.queue.push(fullTask);
    } else {
      this.queue.splice(insertIndex, 0, fullTask);
    }

    this.logger.debug(`Task queued: ${fullTask.id}`, { type: fullTask.type, priority: fullTask.priority });

    // Start processing if not already running
    if (!this.processing) {
      this.processQueue();
    }
  }

  // Process queue tasks sequentially
  private async processQueue(): Promise<void> {
    if (this.processing) return;
    this.processing = true;

    while (this.queue.length > 0) {
      const task = this.queue.shift();
      if (!task) break;

      const handler = this.taskHandlers.get(task.type);
      if (!handler) {
        this.logger.error(`No handler for task type: ${task.type}`);
        continue;
      }

      try {
        this.logger.debug(`Processing task: ${task.id}`);
        await handler(task);
        this.logger.debug(`Task completed: ${task.id}`);
      } catch (error) {
        this.logger.error(`Task failed: ${task.id}`, error);
        
        // Retry with backoff
        if (task.retries < task.max_retries) {
          task.retries++;
          task.priority++; // Lower priority for retries
          this.queue.push(task);
          this.logger.warn(`Task retry ${task.retries}/${task.max_retries}: ${task.id}`);
        }
      }

      // Rate limiting between tasks
      await this.delay(100);
    }

    this.processing = false;
  }

  // Delay helper
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Get current queue length
  getQueueLength(): number {
    return this.queue.length;
  }

  // Clear all tasks from queue
  clear(): void {
    this.queue = [];
  }
}