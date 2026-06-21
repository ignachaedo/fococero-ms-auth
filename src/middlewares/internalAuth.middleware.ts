import { Request, Response, NextFunction } from 'express';
import { envs } from '../config/envs';

export const internalAuthMiddleware = (req: Request, res: Response, next: NextFunction): void => {
    if (req.path === '/health' || req.path === '/metrics' || req.path === '/api/health') {
        return next();
    }

    const internalToken = req.headers['x-internal-token'];

    if (!internalToken || internalToken !== envs.INTERNAL_SECRET_TOKEN) {
        res.status(401).json({
            ok: false,
            error: 'Acceso denegado: Petición interna no autorizada.',
        });
        return;
    }

    next();
};
