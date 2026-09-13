/**
 * Simple in-memory rate limiter middleware
 * No external dependencies, suitable for single-instance deployments
 */

export function createRateLimiter({ windowMs = 60000, max = 60, message = 'Too many requests' } = {}) {
  const buckets = new Map(); // ip -> { count, resetTime }

  // Cleanup old buckets every 5 minutes
  setInterval(() => {
    const now = Date.now();
    for (const [ip, bucket] of buckets) {
      if (now > bucket.resetTime) buckets.delete(ip);
    }
  }, 5 * 60 * 1000).unref();

  return (req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();

    let bucket = buckets.get(ip);
    if (!bucket || now > bucket.resetTime) {
      bucket = { count: 0, resetTime: now + windowMs };
      buckets.set(ip, bucket);
    }

    bucket.count++;

    res.setHeader('X-RateLimit-Limit', max);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, max - bucket.count));
    res.setHeader('X-RateLimit-Reset', new Date(bucket.resetTime).toISOString());

    if (bucket.count > max) {
      return res.status(429).json({
        error: message,
        retryAfter: Math.ceil((bucket.resetTime - now) / 1000),
      });
    }

    next();
  };
}

// Specific limiters for different endpoints
export const scanLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 10,
  message: 'Too many scan requests, please wait a minute',
});

export const apiLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 120,
  message: 'API rate limit exceeded',
});

export const discoveryLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 20,
  message: 'Too many discovery scans',
});
