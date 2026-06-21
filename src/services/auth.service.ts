// ms-auth/src/services/auth.service.ts

import { UserRepository } from '../repositories/user.repository';
import { AuthValidator, GuestRegisterDTO, FullRegisterDTO, LoginDTO, GoogleAuthDTO } from '../validators/auth.validator';
import admin from '../config/firebase';
import { RutHelper } from '../helpers/rut.helper';
import bcrypt from 'bcryptjs';
import { Usuario } from '../models/user.model';
import { UserRole, UserStatus } from '../models/user.enum';
import { AppError } from '../helpers/appError';
import { PerfilBrigadistaRepository } from '../repositories/perfil-brigadista.repository';
import { PerfilBrigadista, UsuarioWithPerfil } from '../models/perfil-brigadista.model';

/**
 * AuthService: Núcleo de lógica del Proveedor de Identidad.
 * Coordina la validación de tokens de Google con la persistencia en PostgreSQL.
 */
export class AuthService {
    // ============================================================================
    // 🟢 SECCIÓN: REGISTRO Y AUTENTICACIÓN
    // ============================================================================

    /**
     * Autentica un usuario por RUT y contraseña (MVP plaintext).
     */
    static async loginUser(data: LoginDTO) {
        const validation = AuthValidator.validateLogin(data);
        if (!validation.isValid) {
            throw new AppError(validation.error || 'Credenciales inválidas', 400);
        }

        const rutFormateado = RutHelper.format(data.rut);
        let user;
        try {
            user = await UserRepository.findByRut(rutFormateado);
        } catch (_error) {
            throw new AppError('Error de base de datos al buscar usuario.', 500);
        }

        if (!user) {
            throw new AppError('Credenciales inválidas.', 401);
        }

        if (!user.password) {
            throw new AppError('Credenciales inválidas.', 401);
        }
        const passwordMatch = await bcrypt.compare(data.password, user.password);
        if (!passwordMatch) {
            throw new AppError('Credenciales inválidas.', 401);
        }

        if (user.estado !== UserStatus.ACTIVO) {
            throw new AppError(
                'Tu cuenta está suspendida o bloqueada. Contacta a soporte.',
                403,
            );
        }

        if (!user.firebase_uid) {
            throw new AppError(
                'Esta cuenta no tiene un identificador Firebase vinculado. Completa tu registro primero.',
                400,
            );
        }

        try {
            await admin.auth().setCustomUserClaims(user.firebase_uid, { rol: user.rol });
        } catch (_error) {
            throw new AppError('Error al sincronizar permisos con Firebase.', 500);
        }

        // Emitir custom token para que el frontend establezca sesión Firebase
        let firebaseToken: string;
        try {
            firebaseToken = await admin.auth().createCustomToken(user.firebase_uid);
        } catch (_error) {
            throw new AppError('Error al generar token de autenticación con Firebase.', 500);
        }

        return { user, firebaseToken };
    }

    /**
     * Registra un usuario invitado (RUT y datos básicos).
     * Si el RUT ya existe, retorna el usuario actual sin crear duplicados.
     */
    static async registerGuestUser(data: GuestRegisterDTO) {
        const validation = AuthValidator.validateGuest(data);
        if (!validation.isValid) {
            throw new AppError(validation.error || 'Datos de invitado inválidos', 400);
        }

        const rutFormateado = RutHelper.format(data.rut);
        let existingUser;
        try {
            existingUser = await UserRepository.findByRut(rutFormateado);
        } catch (_error) {
            throw new AppError('Error de base de datos al verificar usuario existente.', 500);
        }

        if (existingUser) {
            if (data.firebase_uid && !existingUser.firebase_uid) {
                let linked;
                try {
                    linked = await UserRepository.updateFirebaseUid(
                        existingUser.id!,
                        data.firebase_uid,
                        data.fcm_token,
                    );
                } catch (_error) {
                    throw new AppError('Error de base de datos al vincular Firebase UID.', 500);
                }
                return { isNew: false, user: linked || existingUser };
            }
            if (data.firebase_uid && existingUser.firebase_uid === data.firebase_uid) {
                return { isNew: false, user: existingUser };
            }
            return { isNew: false, user: existingUser };
        }

        const userData: Partial<Usuario> = {
            rut: rutFormateado,
            nombre: data.nombre.trim(),
            apellido: data.apellido.trim(),
            telefono: data.telefono.trim(),
            firebase_uid: data.firebase_uid,
            fcm_token: data.fcm_token,
            rol: UserRole.INVITADO,
            estado: UserStatus.ACTIVO,
        };

        if (data.password && data.password.trim().length > 0) {
            const salt = await bcrypt.genSalt(12);
            userData.password = await bcrypt.hash(data.password.trim(), salt);
        }

        let newUser;
        try {
            newUser = await UserRepository.createGuest(userData);
        } catch (_error) {
            throw new AppError('Error de base de datos al crear usuario invitado.', 500);
        }

        let firebaseToken: string | undefined;
        if (newUser.firebase_uid) {
            try {
                await admin.auth().setCustomUserClaims(newUser.firebase_uid, { rol: newUser.rol });
                firebaseToken = await admin.auth().createCustomToken(newUser.firebase_uid);
            } catch (_error) {
                throw new AppError('Error al generar token de autenticación con Firebase.', 500);
            }
        }

        return { isNew: true, user: newUser, firebaseToken };
    }

    /**
     * Upgrade de cuenta guest: establece una contraseña para permitir login RUT+password.
     */
    static async upgradeAccount(firebase_uid: string, password: string) {
        if (!password || password.length < 6) {
            throw new AppError('La contraseña debe tener al menos 6 caracteres.', 400);
        }

        let user;
        try {
            user = await UserRepository.findByFirebaseUid(firebase_uid);
        } catch (_error) {
            throw new AppError('Error de base de datos al buscar usuario.', 500);
        }

        if (!user) {
            throw new AppError('Usuario no encontrado.', 404);
        }

        if (user.password) {
            throw new AppError('Esta cuenta ya tiene una contraseña establecida.', 409);
        }

        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(password.trim(), salt);
        let updated;
        try {
            updated = await UserRepository.update(user.id!, { password: hashedPassword });
        } catch (_error) {
            throw new AppError('Error de base de datos al actualizar contraseña.', 500);
        }

        if (!updated) {
            throw new AppError('Error al actualizar la contraseña en la base de datos.', 500);
        }

        return updated;
    }

    /**
     * Convierte un usuario invitado a ciudadano completo.
     * Establece contraseña y cambia rol de invitado a usuario.
     */
    static async convertGuestToCitizen(firebase_uid: string, password: string) {
        if (!password || password.length < 6) {
            throw new AppError('La contraseña debe tener al menos 6 caracteres.', 400);
        }

        let user;
        try {
            user = await UserRepository.findByFirebaseUid(firebase_uid);
        } catch (_error) {
            throw new AppError('Error de base de datos al buscar usuario.', 500);
        }

        if (!user) {
            throw new AppError('Usuario no encontrado.', 404);
        }

        if (user.rol !== UserRole.INVITADO) {
            throw new AppError('Solo los usuarios invitados pueden completar su registro.', 400);
        }

        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(password.trim(), salt);

        let updated;
        try {
            updated = await UserRepository.update(user.id!, {
                password: hashedPassword,
                rol: UserRole.USUARIO,
            });
        } catch (_error) {
            throw new AppError('Error de base de datos al actualizar usuario.', 500);
        }

        if (!updated) {
            throw new AppError('Error al actualizar el usuario en la base de datos.', 500);
        }

        return updated;
    }

    /**
     * Vincula una cuenta de Google (Firebase) con un perfil de usuario real.
     * Valida la firma criptográfica del token antes de proceder.
     */
    static async registerFullUser(data: FullRegisterDTO) {
        const validation = AuthValidator.validateFullRegister(data);
        if (!validation.isValid) {
            throw new AppError(validation.error || 'Datos de registro completos inválidos', 400);
        }

        const rutFormateado = RutHelper.format(data.rut);

        // Validación criptográfica con Firebase
        let decodedToken;
        try {
            decodedToken = await admin.auth().verifyIdToken(data.token);
        } catch (_error) {
            // ✅ FIX: Prefijo '_' para cumplir con ESLint (error no utilizado)
            throw new AppError('La sesión de Google ha expirado o es inválida.', 401);
        }

        const { uid: firebaseUid, email } = decodedToken;

        // Evitar colisiones de identidad (RUT o UID ya registrados)
        let existingUser;
        try {
            existingUser = await UserRepository.findByFirebaseUidOrRut(
                firebaseUid,
                rutFormateado,
            );
        } catch (_error) {
            throw new AppError('Error de base de datos al verificar identidad.', 500);
        }

        if (existingUser) {
            throw new AppError(
                'Esta cuenta de Google o RUT ya se encuentran registrados en FocoCero.',
                409,
            );
        }

        try {
            const newUser = await UserRepository.createFullUser({
                rut: rutFormateado,
                nombre: data.nombre.trim(),
                apellido: data.apellido.trim(),
                telefono: data.telefono.trim(),
                email: email,
                firebase_uid: firebaseUid,
                rol: UserRole.USUARIO,
                estado: UserStatus.ACTIVO,
            });
            await admin.auth().setCustomUserClaims(firebaseUid, { rol: newUser.rol });
            return { user: newUser };
        } catch (_error) {
            throw new AppError('Error de base de datos al crear usuario completo.', 500);
        }
    }

    static async loginWithGoogle(data: GoogleAuthDTO) {
        if (process.env.NODE_ENV !== 'production') {
            console.log('[GoogleAuth] loginWithGoogle llamado. Token presente:', !!data.token, 'Longitud:', data.token?.length);
        }

        const validation = AuthValidator.validateGoogleAuth(data);
        if (!validation.isValid) {
            throw new AppError(validation.error || 'Token de Google inválido', 400);
        }

        let decodedToken;
        try {
            decodedToken = await admin.auth().verifyIdToken(data.token);
            if (process.env.NODE_ENV !== 'production') {
                console.log('[GoogleAuth] Token verificado. UID:', decodedToken.uid, 'Email:', decodedToken.email);
            }
        } catch {
            throw new AppError('La sesión de Google ha expirado o es inválida.', 401);
        }

        const { uid: firebaseUid, email, name } = decodedToken;

        let user;
        try {
            user = await UserRepository.findByFirebaseUid(firebaseUid);
        } catch (_error) {
            throw new AppError('Error de base de datos al buscar usuario por Firebase UID.', 500);
        }

        if (!user && email) {
            try {
                user = await UserRepository.findByEmail(email);
            } catch (_error) {
                throw new AppError('Error de base de datos al buscar usuario por email.', 500);
            }
        }

        if (user) {
            if (!user.firebase_uid) {
                let updated;
                try {
                    updated = await UserRepository.updateFirebaseUid(user.id!, firebaseUid, undefined);
                } catch (_error) {
                    throw new AppError('Error de base de datos al vincular Firebase UID.', 500);
                }
                const userToReturn = updated || user;
                await admin.auth().setCustomUserClaims(firebaseUid, { rol: userToReturn.rol });
                return { user: userToReturn };
            }
            if (user.estado !== UserStatus.ACTIVO) {
                throw new AppError('Tu cuenta está suspendida o bloqueada.', 403);
            }
            await admin.auth().setCustomUserClaims(user.firebase_uid, { rol: user.rol });
            return { user };
        }

        const nombre = name?.split(' ')[0] || 'Usuario';
        const apellido = name?.split(' ').slice(1).join(' ') || 'Google';

        const placeholderRut = `GG${firebaseUid.slice(-9).toUpperCase()}`;

        try {
            const newUser = await UserRepository.createFullUser({
                rut: placeholderRut,
                nombre,
                apellido,
                telefono: '',
                email: email || '',
                firebase_uid: firebaseUid,
                rol: UserRole.USUARIO,
                estado: UserStatus.ACTIVO,
            });
            await admin.auth().setCustomUserClaims(firebaseUid, { rol: newUser.rol });
            return { user: newUser };
        } catch (_error) {
            throw new AppError('Error de base de datos al crear usuario desde Google.', 500);
        }
    }

    // ============================================================================
    // 🔵 SECCIÓN: CONSULTAS Y PERFILES
    // ============================================================================

    static async getUserProfile(userId: number) {
        let user;
        try {
            user = await UserRepository.findById(userId);
        } catch (_error) {
            throw new AppError('Error de base de datos al obtener perfil.', 500);
        }
        if (!user) {
            throw new AppError('No se encontró el perfil del usuario.', 404);
        }
        return user;
    }

    static async getUserStats(userId: number) {
        let user;
        try {
            user = await UserRepository.findById(userId);
        } catch (_error) {
            throw new AppError('Error de base de datos al obtener usuario.', 500);
        }
        if (!user) {
            throw new AppError('Usuario no encontrado.', 404);
        }

        return {
            totalReportes: 0,
            alertasActivas: 0,
            ultimaActividad: user.updated_at || user.created_at,
            reputacion: user.reputacion || 0,
        };
    }

    static async getAllUsersForAdmin() {
        try {
            return await UserRepository.findAll();
        } catch (_error) {
            throw new AppError('Error de base de datos al listar usuarios.', 500);
        }
    }

    // ============================================================================
    // 🟡 SECCIÓN: ACTUALIZACIONES Y ESTADOS
    // ============================================================================

    /**
     * Actualiza el perfil permitiendo solo cambios en campos no sensibles.
     */
    static async updateUserProfile(userId: number, updateData: Partial<Usuario>) {
        // Bloqueo de seguridad: No se puede cambiar rol o estado por esta vía
        delete updateData.rol;
        delete updateData.estado;
        delete updateData.firebase_uid;

        let user;
        try {
            user = await UserRepository.findById(userId);
        } catch (_error) {
            throw new AppError('Error de base de datos al buscar usuario.', 500);
        }
        if (!user) {
            throw new AppError('Usuario inexistente.', 404);
        }

        // Si cambia el RUT, verificar que no pertenezca a otro usuario
        if (updateData.rut) {
            updateData.rut = RutHelper.format(updateData.rut);
            let duplicate;
            try {
                duplicate = await UserRepository.findByRut(updateData.rut);
            } catch (_error) {
                throw new AppError('Error de base de datos al verificar RUT duplicado.', 500);
            }
            if (duplicate && duplicate.id !== userId) {
                throw new AppError('El RUT ingresado ya está vinculado a otra cuenta.', 409);
            }
        }

        if (updateData.nombre) updateData.nombre = updateData.nombre.trim();
        if (updateData.apellido) updateData.apellido = updateData.apellido.trim();

        let updated;
        try {
            updated = await UserRepository.update(userId, updateData);
        } catch (_error) {
            throw new AppError('Error de base de datos al actualizar perfil.', 500);
        }
        if (!updated) {
            throw new AppError('Error al actualizar el perfil en la base de datos.', 500);
        }

        return updated;
    }

    static async changeUserRole(userId: number, newRole: UserRole) {
        if (!Object.values(UserRole).includes(newRole)) {
            throw new AppError('El rol especificado no existe en el sistema.', 400);
        }
        try {
            const updated = await UserRepository.update(userId, { rol: newRole });

            // Auto-create perfil_brigadista if role is BRIGADISTA
            if (newRole === UserRole.BRIGADISTA) {
                const existing = await PerfilBrigadistaRepository.findByUsuarioId(userId);
                if (!existing) {
                    await PerfilBrigadistaRepository.create({ usuario_id: userId });
                }
            }

            return updated;
        } catch (_error) {
            throw new AppError('Error de base de datos al cambiar rol.', 500);
        }
    }

    static async updateUserStatus(userId: number, newStatus: UserStatus) {
        if (!Object.values(UserStatus).includes(newStatus)) {
            throw new AppError('El estado especificado es inválido.', 400);
        }
        try {
            return await UserRepository.update(userId, { estado: newStatus });
        } catch (_error) {
            throw new AppError('Error de base de datos al cambiar estado.', 500);
        }
    }

    /**
     * Sincroniza el token de Firebase Cloud Messaging para notificaciones push.
     */
    static async syncFcmToken(userId: number, fcmToken: string) {
        if (!fcmToken || fcmToken.trim().length < 10) {
            throw new AppError('El token FCM proporcionado es inválido.', 400);
        }
        try {
            await UserRepository.updateFcmToken(userId, fcmToken);
        } catch (_error) {
            throw new AppError('Error de base de datos al sincronizar token FCM.', 500);
        }
    }

    // ============================================================================
    // 🔴 SECCIÓN: ELIMINACIÓN
    // ============================================================================

    static async terminateUser(userId: number) {
        let user;
        try {
            user = await UserRepository.findById(userId);
        } catch (_error) {
            throw new AppError('Error de base de datos al buscar usuario.', 500);
        }
        if (!user) {
            throw new AppError('Operación fallida: Usuario no encontrado.', 404);
        }

        try {
            return await UserRepository.delete(userId);
        } catch (_error) {
            throw new AppError('Error de base de datos al eliminar usuario.', 500);
        }
    }

    // ============================================================================
    // 🟠 SECCIÓN: PERFIL BRIGADISTA
    // ============================================================================

    static async getPerfilBrigadista(userId: number): Promise<UsuarioWithPerfil> {
        const user = await this.getUserProfile(userId); // reuse
        const perfil = await PerfilBrigadistaRepository.findByUsuarioId(userId);
        return { ...user, perfil_brigadista: perfil || null };
    }

    static async updatePerfilBrigadista(userId: number, updateData: Partial<PerfilBrigadista>): Promise<UsuarioWithPerfil> {
        const user = await this.getUserProfile(userId);

        // Allowed fields only
        const allowedFields: (keyof PerfilBrigadista)[] = ['organismo', 'rango', 'zona_asignada', 'numero_placa', 'fecha_ingreso'];
        const filteredData: Partial<PerfilBrigadista> = {};
        for (const key of allowedFields) {
            if (updateData[key] !== undefined) {
                (filteredData as Record<string, unknown>)[key] = updateData[key];
            }
        }

        if (Object.keys(filteredData).length === 0) {
            throw new AppError('No se proporcionaron campos válidos para actualizar.', 400);
        }

        const updated = await PerfilBrigadistaRepository.update(userId, filteredData);
        if (!updated) {
            throw new AppError('Error al actualizar perfil de brigadista.', 500);
        }

        return { ...user, perfil_brigadista: updated };
    }

    static async adminCreateBrigadista(userId: number, perfilData: Partial<PerfilBrigadista>): Promise<UsuarioWithPerfil> {
        const user = await this.getUserProfile(userId);

        // Check if profile already exists
        const existing = await PerfilBrigadistaRepository.findByUsuarioId(userId);
        if (existing) {
            throw new AppError('El usuario ya tiene un perfil de brigadista.', 409);
        }

        // Create profile with defaults
        const data: Partial<PerfilBrigadista> = {
            usuario_id: userId,
            organismo: perfilData.organismo || '',
            rango: perfilData.rango || '',
            zona_asignada: perfilData.zona_asignada || '',
            numero_placa: perfilData.numero_placa || '',
            fecha_ingreso: perfilData.fecha_ingreso || new Date().toISOString().split('T')[0],
        };

        const perfil = await PerfilBrigadistaRepository.create(data);

        // Also update user's role to BRIGADISTA if not already
        if (user.rol !== UserRole.BRIGADISTA) {
            await UserRepository.update(userId, { rol: UserRole.BRIGADISTA });
        }

        return { ...user, perfil_brigadista: perfil, rol: UserRole.BRIGADISTA };
    }
}
