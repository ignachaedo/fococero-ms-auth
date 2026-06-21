// ms-auth/src/controllers/auth.controller.ts

import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../services/auth.service';
import { AuthValidator } from '../validators/auth.validator';
import { AppError } from '../helpers/appError';

export class AuthController {
    // --- 🟢 SECCIÓN: PÚBLICA ---
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
    static async getProfile(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const userId = req.user!.id!;
            const profile = await AuthService.getUserProfile(userId);
            res.status(200).json({ ok: true, usuario: profile });
        } catch (error) {
            next(error);
        }
    }

    static async updateProfile(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const userId = req.user!.id!;
            const updatedUser = await AuthService.updateUserProfile(userId, req.body);
            res.status(200).json({ ok: true, msg: 'Perfil actualizado', usuario: updatedUser });
        } catch (error) {
            next(error);
        }
    }

    static async syncFcmToken(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const userId = req.user!.id!;
            await AuthService.syncFcmToken(userId, req.body.fcmToken);
            res.status(200).json({ ok: true, msg: 'Canal de alertas push sincronizado' });
        } catch (error) {
            next(error);
        }
    }

    static async getMyStats(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const userId = req.user!.id!;
            const stats = await AuthService.getUserStats(userId);
            res.status(200).json({ ok: true, data: stats });
        } catch (error) {
            next(error);
        }
    }

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

    static async getMyNotifications(_req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            res.status(200).json({ ok: true, data: [] });
        } catch (error) {
            next(error);
        }
    }

    // --- Perfil Brigadista ---
    static async getMyPerfilBrigadista(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const userId = req.user!.id!;
            const result = await AuthService.getPerfilBrigadista(userId);
            res.status(200).json({ ok: true, usuario: result });
        } catch (error) {
            next(error);
        }
    }

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
    static async getAllUsers(_req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const users = await AuthService.getAllUsersForAdmin();
            res.status(200).json({ ok: true, total: users.length, usuarios: users });
        } catch (error) {
            next(error);
        }
    }

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
