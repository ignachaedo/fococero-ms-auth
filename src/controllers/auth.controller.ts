/**
 * @fileoverview Controlador de autenticación y gestión de usuarios.
 * Expone los endpoints HTTP para login, registro (invitado/completo/Google),
 * gestión de perfil, roles, brigadistas y administración de usuarios.
 * Delega toda la lógica de negocio a AuthService.
 */

import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../services/auth.service';
import { AuthValidator } from '../validators/auth.validator';
import { AppError } from '../helpers/appError';

export class AuthController {
    // --- 🟢 SECCIÓN: PÚBLICA ---

    /**
     * Inicia sesión con RUT y contraseña.
     *
     * @param req - Request con body { rut, password }
     * @param res - Response con { ok, msg, usuario, firebaseToken }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async login(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const { user, firebaseToken } = await AuthService.loginUser(req.body);
            res.status(200).json({
                ok: true,
                msg: 'Inicio de sesión exitoso',
                usuario: user,
                firebaseToken,
            });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Registra un nuevo usuario invitado con datos básicos.
     *
     * @param req - Request con body { rut, nombre, apellido, telefono, password?, firebase_uid? }
     * @param res - Response con { ok, msg, usuario, firebaseToken? }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async registerGuest(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await AuthService.registerGuestUser(req.body);
            const statusCode = result.isNew ? 201 : 200;
            const msg = result.isNew
                ? 'Usuario registrado exitosamente'
                : 'Usuario ya identificado en el sistema';

            const response: Record<string, unknown> = { ok: true, msg, usuario: result.user };
            if ('firebaseToken' in result && result.firebaseToken) {
                response.firebaseToken = result.firebaseToken;
            }

            res.status(statusCode).json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Establece una contraseña para una cuenta invitada existente.
     *
     * @param req - Request con body { password } y usuario autenticado en req.user
     * @param res - Response con { ok, msg, usuario }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async upgradeAccount(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const firebase_uid = req.user?.firebase_uid;
            if (!firebase_uid) throw new AppError('Usuario no autenticado', 401);
            const { password } = req.body;
            const updatedUser = await AuthService.upgradeAccount(firebase_uid, password);
            res.status(200).json({ ok: true, msg: 'Contraseña establecida exitosamente', usuario: updatedUser });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Registra un usuario completo con RUT, datos personales y vinculación con Google.
     *
     * @param req - Request con body { token, rut, nombre, apellido, telefono }
     * @param res - Response con { ok, msg, usuario }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async registerFull(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const { user } = await AuthService.registerFullUser(req.body);
            res.status(201).json({
                ok: true,
                msg: 'Cuenta FocoCero creada con éxito',
                usuario: user,
            });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Inicia sesión o registra un usuario mediante Google Sign-In.
     *
     * @param req - Request con body { token } (Firebase ID Token)
     * @param res - Response con { ok, msg, usuario }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async loginWithGoogle(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
                throw new AppError('El cuerpo de la solicitud es requerido para autenticación con Google.', 400);
            }
            const { user } = await AuthService.loginWithGoogle(req.body);
            res.status(200).json({
                ok: true,
                msg: 'Inicio de sesión con Google exitoso',
                usuario: user,
            });
        } catch (error) {
            next(error);
        }
    }

    // --- 🔵 SECCIÓN: PRIVADA ---

    /**
     * Obtiene el perfil del usuario autenticado.
     *
     * @param req - Request con usuario autenticado en req.user
     * @param res - Response con { ok, usuario }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async getProfile(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const userId = req.user!.id!;
            const profile = await AuthService.getUserProfile(userId);
            res.status(200).json({ ok: true, usuario: profile });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Actualiza el perfil del usuario autenticado.
     *
     * @param req - Request con usuario autenticado y body con campos a actualizar
     * @param res - Response con { ok, msg, usuario }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async updateProfile(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const userId = req.user!.id!;
            const updatedUser = await AuthService.updateUserProfile(userId, req.body);
            res.status(200).json({ ok: true, msg: 'Perfil actualizado', usuario: updatedUser });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Sincroniza el token FCM para notificaciones push del dispositivo.
     *
     * @param req - Request con body { fcmToken }
     * @param res - Response con { ok, msg }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async syncFcmToken(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const userId = req.user!.id!;
            await AuthService.syncFcmToken(userId, req.body.fcmToken);
            res.status(200).json({ ok: true, msg: 'Canal de alertas push sincronizado' });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Obtiene estadísticas del usuario autenticado.
     *
     * @param req - Request con usuario autenticado
     * @param res - Response con { ok, data }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async getMyStats(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const userId = req.user!.id!;
            const stats = await AuthService.getUserStats(userId);
            res.status(200).json({ ok: true, data: stats });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Convierte una cuenta invitada a ciudadano (establece contraseña y cambia rol).
     *
     * @param req - Request con body { password } y usuario autenticado
     * @param res - Response con { ok, msg, usuario }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async convertToCiudadano(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const firebase_uid = req.user?.firebase_uid;
            if (!firebase_uid) throw new AppError('Usuario no autenticado', 401);
            const { password } = req.body;
            const updatedUser = await AuthService.convertGuestToCitizen(firebase_uid, password);
            res.status(200).json({
                ok: true,
                msg: 'Cuenta convertida a ciudadano exitosamente',
                usuario: updatedUser,
            });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Obtiene las notificaciones del usuario autenticado.
     *
     * @param _req - Request (no utilizado actualmente, retorna array vacío)
     * @param res - Response con { ok, data: [] }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async getMyNotifications(_req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            res.status(200).json({ ok: true, data: [] });
        } catch (error) {
            next(error);
        }
    }

    // --- Perfil Brigadista ---

    /**
     * Obtiene el perfil de brigadista del usuario autenticado.
     *
     * @param req - Request con usuario autenticado
     * @param res - Response con { ok, usuario }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async getMyPerfilBrigadista(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const userId = req.user!.id!;
            const result = await AuthService.getPerfilBrigadista(userId);
            res.status(200).json({ ok: true, usuario: result });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Actualiza el perfil de brigadista del usuario autenticado.
     *
     * @param req - Request con body con campos a actualizar del perfil
     * @param res - Response con { ok, msg, usuario }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async updateMyPerfilBrigadista(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const userId = req.user!.id!;
            const validation = AuthValidator.validatePerfilBrigadista(req.body ?? {});
            if (!validation.isValid) {
                throw new AppError(validation.error!, 400);
            }
            const result = await AuthService.updatePerfilBrigadista(userId, req.body);
            res.status(200).json({ ok: true, msg: 'Perfil de brigadista actualizado', usuario: result });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Crea un perfil de brigadista para un usuario específico (solo administradores).
     *
     * @param req - Request con params.id (ID del usuario) y body con datos del perfil
     * @param res - Response con { ok, msg, usuario }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async adminCreateBrigadista(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const targetUserId = parseInt(String(req.params.id), 10);
            if (isNaN(targetUserId) || targetUserId <= 0) {
                throw new AppError('ID de usuario inválido', 400);
            }
            const result = await AuthService.adminCreateBrigadista(targetUserId, req.body);
            res.status(201).json({
                ok: true,
                msg: 'Brigadista creado exitosamente',
                usuario: result,
            });
        } catch (error) {
            next(error);
        }
    }

    // --- 🔴 SECCIÓN: ADMINISTRATIVA ---

    /**
     * Obtiene todos los usuarios registrados (solo administradores).
     *
     * @param _req - Request (no utilizado)
     * @param res - Response con { ok, total, usuarios }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async getAllUsers(_req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const users = await AuthService.getAllUsersForAdmin();
            res.status(200).json({ ok: true, total: users.length, usuarios: users });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Cambia el rol de un usuario (solo administradores).
     *
     * @param req - Request con params.id y body.rol
     * @param res - Response con { ok, msg, usuario }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async changeRole(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            // ✅ FIX: Casteo explícito a String primitivo
            const targetUserId = parseInt(String(req.params.id), 10);
            if (isNaN(targetUserId) || targetUserId <= 0) {
                throw new AppError('ID de usuario inválido', 400);
            }
            const updatedUser = await AuthService.changeUserRole(targetUserId, req.body.rol);
            res.status(200).json({
                ok: true,
                msg: 'Rol actualizado exitosamente',
                usuario: updatedUser,
            });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Cambia el estado de un usuario (solo administradores).
     *
     * @param req - Request con params.id y body.estado
     * @param res - Response con { ok, msg, usuario }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async changeStatus(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            // ✅ FIX: Casteo explícito a String primitivo
            const targetUserId = parseInt(String(req.params.id), 10);
            if (isNaN(targetUserId) || targetUserId <= 0) {
                throw new AppError('ID de usuario inválido', 400);
            }
            const updatedUser = await AuthService.updateUserStatus(targetUserId, req.body.estado);
            res.status(200).json({
                ok: true,
                msg: 'Estado operativo modificado',
                usuario: updatedUser,
            });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Elimina físicamente un usuario del sistema (solo administradores).
     *
     * @param req - Request con params.id
     * @param res - Response con { ok, msg }
     * @param next - NextFunction para pasar errores al manejador global
     */
    static async deleteUser(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            // ✅ FIX: Casteo explícito a String primitivo
            const targetUserId = parseInt(String(req.params.id), 10);
            if (isNaN(targetUserId) || targetUserId <= 0) {
                throw new AppError('ID de usuario inválido', 400);
            }
            await AuthService.terminateUser(targetUserId);
            res.status(200).json({
                ok: true,
                msg: `Usuario con ID ${targetUserId} eliminado definitivamente.`,
            });
        } catch (error) {
            next(error);
        }
    }
}
