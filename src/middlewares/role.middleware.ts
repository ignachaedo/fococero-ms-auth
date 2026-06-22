/**
 * @fileoverview Middleware de autorización basada en roles (RBAC) para ms-auth.
 * Verifica que el usuario autenticado tenga el rol necesario para acceder
 * a rutas protegidas. Implementa control de acceso granular.
 */

import { Request, Response, NextFunction } from 'express';
import { UserRole } from '../models/user.enum';

/**
 * Middleware: Autorización Basada en Roles (RBAC)
 * Evalúa si el usuario autenticado tiene los privilegios necesarios para ejecutar una acción.
 *
 * @description Factory function que retorna un middleware. Compara el rol del usuario
 * autenticado (req.user.rol) contra la lista de roles permitidos.
 * Si req.user no existe, responde 401. Si el rol no está en la lista, responde 403.
 *
 * @param allowedRoles - Array de roles permitidos para acceder a la ruta
 * @returns Middleware function de Express
 */
export const authorizeRole = (allowedRoles: UserRole[]) => {
    return (req: Request, res: Response, next: NextFunction): void => {
        // ✅ FIX: Autocompletado nativo y tipado estricto sin usar 'any'
        const user = req.user;

        if (!user) {
            res.status(401).json({
                ok: false,
                msg: 'Acceso denegado: Identidad no verificada en el flujo.',
            });
            return;
        }

        if (!allowedRoles.includes(user.rol as UserRole)) {
            res.status(403).json({
                ok: false,
                msg: `Acceso denegado: Requiere nivel de privilegio superior. Tu rol actual es '${user.rol}'.`,
            });
            return;
        }

        next();
    };
};
