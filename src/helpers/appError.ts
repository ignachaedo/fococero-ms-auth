/**
 * @fileoverview Clase personalizada para errores operacionales.
 * Permite diferenciar errores esperados (de negocio/validación) de errores
 * inesperados (bugs) en el manejador global de errores.
 */

/**
 * AppError: Error operacional con código HTTP.
 *
 * @description Extiende Error para incluir statusCode HTTP y un flag isOperational
 * que permite al manejador global de errores distinguir entre errores esperados
 * (errores de negocio, validación, autenticación) y errores inesperados (bugs).
 * Los errores operacionales se retornan al cliente con el mensaje y código definidos.
 *
 * @example throw new AppError('Usuario no encontrado', 404);
 */
export class AppError extends Error {
    /** Código HTTP del error */
    public readonly statusCode: number;
    /** Indica si es un error operacional esperado (true) o inesperado (false) */
    public readonly isOperational: boolean;

    /**
     * Crea una nueva instancia de AppError.
     *
     * @param message - Mensaje descriptivo del error
     * @param statusCode - Código HTTP a retornar
     */
    constructor(message: string, statusCode: number) {
        super(message);
        this.statusCode = statusCode;
        this.isOperational = true;
        Error.captureStackTrace(this, this.constructor);
    }
}
