/**
 * @fileoverview Middleware de autenticación operativa para ms-auth.
 * Valida la firma criptográfica del token JWT de Firebase, recupera el perfil
 * completo del usuario desde PostgreSQL, verifica su estado, y lo inyecta en req.user.
 */

import { Request, Response, NextFunction } from 'express';
import admin from '../config/firebase';
import { UserRepository } from '../repositories/user.repository';
import { UserStatus } from '../models/user.enum';

/**
 * Middleware: Autenticación Operativa (Identity Provider)
 * Intercepta peticiones privadas, valida la firma criptográfica de Google y
 * recupera el perfil completo del usuario de la base de datos (PostgreSQL).
 *
 * @description Escudo perimetral en 5 capas:
 * 1. Rechazo temprano si no hay token Bearer
 * 2. Verificación criptográfica con Firebase Admin
 * 3. Búsqueda del usuario en PostgreSQL por Firebase UID
 * 4. Verificación del ciclo de vida del usuario (estado ACTIVO)
 * 5. Inyección tipada del objeto Usuario completo en req.user
 *
 * @param req - Objeto Request de Express
 * @param res - Objeto Response de Express
 * @param next - Función NextFunction de Express
 * @returns Promise<void> - No retorna valor, pasa al siguiente middleware o responde error
 * @throws Error - Errores de Firebase (token expirado/inválido) se delegan al error middleware
 */
export const validateFirebaseToken = async (
    req: Request,
    res: Response,
    next: NextFunction,
): Promise<void> => {
    try {
        // 1. Escudo Perimetral: Rechazo temprano si no hay token
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            res.status(401).json({
                ok: false,
                error: 'Acceso denegado: Token Bearer no proporcionado.',
            });
            return;
        }

        const token = authHeader.split(' ')[1];

        // 2. Escudo Criptográfico: Verificación contra los servidores de Google
        const decodedToken = await admin.auth().verifyIdToken(token);

        // 3. Escudo de Identidad Local: Buscar al usuario en nuestro PostgreSQL
        const user = await UserRepository.findByFirebaseUid(decodedToken.uid);

        if (!user) {
            res.status(403).json({
                ok: false,
                error: 'Identidad de Google válida, pero el usuario no está registrado en el ecosistema FocoCero.',
            });
            return;
        }

        // 4. Protección Enterprise: Verificar ciclo de vida del usuario
        if (user.estado !== UserStatus.ACTIVO) {
            res.status(403).json({
                ok: false,
                error: `Cuenta inhabilitada. Estado actual: ${user.estado}. Contacte a soporte técnico.`,
            });
            return;
        }

        // 5. Inyección Tipada: Delegamos el objeto 'Usuario' completo a la Request.
        // Gracias a tu index.d.ts, TypeScript autocompletará req.user en los controladores.
        req.user = user;

        next();
    } catch (error: unknown) {
        // Delegamos errores de caducidad o falsificación al error.middleware.ts
        next(error);
    }
};
