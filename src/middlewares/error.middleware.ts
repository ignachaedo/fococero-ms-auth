/**
 * @fileoverview Manejador global de errores para ms-auth.
 * Centraliza la captura de excepciones, traduce errores de Firebase Auth
 * (tokens expirados, inválidos, usuario no encontrado) y retorna respuestas
 * estandarizadas sin exponer detalles internos del servidor.
 */

import { Request, Response, NextFunction } from 'express';
import { logger } from '../config/logger';
import { AppError } from '../helpers/appError';

/**
 * Middleware: Manejador Global de Errores (Error Catcher)
 * Evita que la aplicación colapse centralizando las respuestas de error.
 * Regla de oro: self-protection — nunca exponer detalles internos al cliente.
 *
 * @description Si el error no es un AppError operacional, retorna 500 genérico.
 * Para errores de Firebase con código 'auth/', traduce a mensajes legibles.
 *
 * @param err - Error capturado (puede ser AppError, Error de Firebase, etc.)
 * @param _req - Objeto Request de Express (no utilizado)
 * @param res - Objeto Response de Express
 * @param _next - Función NextFunction de Express (no utilizada)
 */
export const errorHandler = (
    err: unknown,
    _req: Request,
    res: Response,
    _next: NextFunction,
): void => {
    // Self-protection: si el error NO es un AppError operacional conocido,
    // retornamos 500 con mensaje genérico para no filtrar detalles internos.
    if (!(err instanceof AppError)) {
        logger.error(
            { err },
            '🚨 [Error Global Handler ms-auth] Error no operacional capturado',
        );
        res.status(500).json({
            ok: false,
            error: 'Error interno del servidor. Contacte al equipo de FocoCero.',
        });
        return;
    }

    // 1. Log interno del servidor (Para trazabilidad)
    logger.error({ err }, `🚨 [Error Global Handler ms-auth]`);

    let statusCode = err.statusCode || 500;
    let message = err.message || 'Error interno del servidor. Contacte al equipo de FocoCero.';

    // --- 🟢 EVALUACIÓN DE ERRORES FIREBASE ---
    if (
        err instanceof Object
        && 'code' in err
        && typeof (err as Record<string, unknown>).code === 'string'
        && ((err as Record<string, unknown>).code as string).startsWith('auth/')
    ) {
        statusCode = 401;
        const errorCode = (err as Record<string, unknown>).code as string;
        switch (errorCode) {
            case 'auth/id-token-expired':
                message =
                    'Tu sesión ha expirado por seguridad. Por favor, inicia sesión nuevamente.';
                break;
            case 'auth/argument-error':
            case 'auth/invalid-id-token':
                message = 'El token de acceso proporcionado está corrupto o es inválido.';
                break;
            case 'auth/user-not-found':
                message =
                    'La credencial vinculada a este token ya no existe en los registros de Google.';
                break;
            default:
                message = 'Fallo en la validación de identidad. Verifica tus credenciales.';
        }
    }

    res.status(statusCode).json({
        ok: false,
        error: message,
    });
};
