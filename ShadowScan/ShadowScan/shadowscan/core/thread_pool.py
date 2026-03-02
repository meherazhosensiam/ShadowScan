#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowScan Thread Pool Manager
Author: Meheraz HOSEN SIAM
Description: Optimized thread pool management for high-performance scanning
"""

import threading
import queue
import time
from typing import Callable, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from dataclasses import dataclass
from datetime import datetime


@dataclass
class TaskResult:
    """Result from a scan task"""
    task_id: int
    result: Any
    error: Optional[str] = None
    duration: float = 0.0


class ThreadPoolManager:
    """
    Optimized thread pool manager for network scanning operations.
    
    Features:
    - Dynamic thread adjustment
    - Task batching for efficiency
    - Progress tracking
    - Graceful shutdown
    - Resource management
    """
    
    def __init__(self, max_workers: int = 100, batch_size: int = 50,
                 timeout: float = 1.0, max_retries: int = 2):
        self.max_workers = max_workers
        self.batch_size = batch_size
        self.timeout = timeout
        self.max_retries = max_retries
        self._shutdown = False
        self._lock = threading.Lock()
        self._results_queue = queue.Queue()
        self._active_threads = 0
        self._completed_tasks = 0
        self._failed_tasks = 0
        
    def _get_optimal_workers(self, total_tasks: int) -> int:
        """Calculate optimal number of workers based on task count"""
        import os
        cpu_count = os.cpu_count() or 4
        
        # For network I/O bound tasks, we can use more threads than CPU cores
        # But we should limit based on total tasks to avoid overhead
        if total_tasks <= 10:
            return min(total_tasks, cpu_count * 2)
        elif total_tasks <= 100:
            return min(self.max_workers, cpu_count * 10)
        else:
            return min(self.max_workers, cpu_count * 20)
    
    def submit_batch(self, func: Callable, items: List[Any],
                     callback: Optional[Callable] = None,
                     progress_callback: Optional[Callable] = None) -> List[TaskResult]:
        """
        Submit a batch of tasks and collect results.
        
        Args:
            func: Function to execute for each item
            items: List of items to process
            callback: Optional callback for each completed task
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of TaskResult objects
        """
        optimal_workers = self._get_optimal_workers(len(items))
        results = []
        
        start_time = time.time()
        
        try:
            with ThreadPoolExecutor(max_workers=optimal_workers) as executor:
                futures = {}
                
                for i, item in enumerate(items):
                    if self._shutdown:
                        break
                    future = executor.submit(self._wrap_task, func, i, item)
                    futures[future] = (i, item)
                
                for future in as_completed(futures):
                    if self._shutdown:
                        break
                        
                    try:
                        result = future.result(timeout=self.timeout * 2)
                        results.append(result)
                        
                        with self._lock:
                            self._completed_tasks += 1
                        
                        if callback:
                            callback(result)
                            
                        if progress_callback:
                            progress = (self._completed_tasks / len(items)) * 100
                            progress_callback(progress, self._completed_tasks, len(items))
                            
                    except Exception as e:
                        with self._lock:
                            self._failed_tasks += 1
                        results.append(TaskResult(
                            task_id=futures[future][0],
                            result=None,
                            error=str(e)
                        ))
                        
        except KeyboardInterrupt:
            self._shutdown = True
            
        return results
    
    def _wrap_task(self, func: Callable, task_id: int, item: Any) -> TaskResult:
        """Wrap a task with timing and error handling"""
        start = time.time()
        
        for attempt in range(self.max_retries + 1):
            try:
                result = func(item)
                duration = time.time() - start
                return TaskResult(task_id=task_id, result=result, duration=duration)
            except Exception as e:
                if attempt == self.max_retries:
                    duration = time.time() - start
                    return TaskResult(task_id=task_id, result=None, error=str(e), duration=duration)
                time.sleep(0.1 * (attempt + 1))  # Exponential backoff
        
        return TaskResult(task_id=task_id, result=None, error="Max retries exceeded")
    
    def shutdown(self, wait: bool = True) -> None:
        """Gracefully shutdown the thread pool"""
        self._shutdown = True
    
    def get_stats(self) -> dict:
        """Get thread pool statistics"""
        return {
            'max_workers': self.max_workers,
            'completed_tasks': self._completed_tasks,
            'failed_tasks': self._failed_tasks,
            'active_threads': self._active_threads
        }


class RateLimiter:
    """Rate limiter for controlling scan speed"""
    
    def __init__(self, max_rate: int = 1000):
        """
        Initialize rate limiter.
        
        Args:
            max_rate: Maximum requests per second
        """
        self.max_rate = max_rate
        self.min_interval = 1.0 / max_rate
        self._lock = threading.Lock()
        self._last_time = 0.0
        
    def acquire(self) -> None:
        """Acquire permission to proceed (blocks if rate limit exceeded)"""
        with self._lock:
            current = time.time()
            wait_time = self._last_time + self.min_interval - current
            
            if wait_time > 0:
                time.sleep(wait_time)
                
            self._last_time = time.time()


class PortQueue:
    """Thread-safe port queue for distributed scanning"""
    
    def __init__(self, ports: List[int]):
        self._queue = queue.Queue()
        self._total = len(ports)
        self._processed = 0
        self._lock = threading.Lock()
        
        for port in ports:
            self._queue.put(port)
    
    def get(self, timeout: float = 1.0) -> Optional[int]:
        """Get next port from queue"""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def task_done(self) -> None:
        """Mark task as complete"""
        with self._lock:
            self._processed += 1
        self._queue.task_done()
    
    def get_progress(self) -> tuple:
        """Get scan progress"""
        return self._processed, self._total
    
    def is_empty(self) -> bool:
        """Check if queue is empty"""
        return self._queue.empty()
