/**
 * @fileoverview Middleware de métricas Prometheus para ms-auth.
 * Registra contadores de requests HTTP y duración con labels de método, ruta y status code.
 * Expone endpoint /metrics para scraping por Prometheus.
 */

import { Request, Response, NextFunction } from 'express';
import client from 'prom-client';

const register = new client.Registry();

client.collectDefaultMetrics({ register });

const httpRequestCounter = new client.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status'],
  registers: [register],
});

const httpRequestDuration = new client.Histogram({
  name: 'http_request_duration_ms',
  help: 'HTTP request duration in ms',
  labelNames: ['method', 'route', 'status'],
  buckets: [50, 100, 200, 500, 1000, 2000, 5000],
  registers: [register],
});

/**
 * Middleware que mide duración y cuenta requests HTTP.
 * Se ejecuta en el evento 'finish' de la respuesta.
 *
 * @param req - Objeto de solicitud Express
 * @param res - Objeto de respuesta Express
 * @param next - Función next de Express
 */
export const metricsMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    httpRequestCounter.inc({ method: req.method, route: req.route?.path || req.path, status: res.statusCode });
    httpRequestDuration.observe({ method: req.method, route: req.route?.path || req.path, status: res.statusCode }, duration);
  });
  next();
};

/**
 * Handler para el endpoint /metrics de Prometheus.
 *
 * @param _req - Objeto de solicitud Express (no utilizado)
 * @param res - Objeto de respuesta Express
 */
export const metricsHandler = async (_req: Request, res: Response) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
};
