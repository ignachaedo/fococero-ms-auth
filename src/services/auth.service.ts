/**
 * @fileoverview Servicio de autenticación y gestión de usuarios (Identity Provider).
 * Coordina la validación de tokens de Firebase con la persistencia en PostgreSQL.
 * Implementa registro de invitados, registro completo con Google, upgrade de cuentas,
 * administración de roles, perfiles de brigadista, y sincronización con Firebase Custom Claims.
 */

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
     * Autentica un usuario por RUT y contraseña.
     *
     * @description Valida credenciales contra la base de datos usando bcrypt,
     * verifica el estado activo del usuario, sincroniza custom claims en Firebase,
     * y genera un Firebase Custom Token para establecer sesión en el frontend.
     *
     * @param data - DTO con RUT y contraseña del usuario
     * @param data.rut - RUT del usuario (formato chileno)
     * @param data.password - Contraseña en texto plano
     * @returns Objeto con datos del usuario y Firebase Custom Token
     * @throws AppError(400) - Si faltan credenciales o RUT sin Firebase UID
     * @throws AppError(401) - Si credenciales inválidas o usuario no encontrado
     * @throws AppError(403) - Si cuenta suspendida o bloqueada
     * @throws AppError(500) - Error de base de datos o Firebase
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
     *
     * @description Crea un nuevo usuario con rol INVITADO. Si el RUT ya existe,
     * vincula el firebase_uid si el usuario existente aún no tiene uno.
     * Si se proporciona contraseña, la hashea con bcrypt antes de persistir.
     * Genera Firebase Custom Token si el usuario tiene firebase_uid.
     *
     * @param data - DTO con datos del invitado (RUT, nombre, apellido, teléfono, password opcional, firebase_uid opcional)
     * @returns Objeto con indicador isNew, datos del usuario y firebaseToken opcional
     * @throws AppError(400) - Si datos de invitado inválidos según validador
     * @throws AppError(500) - Error de base de datos o Firebase
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
     *
     * @description Permite a un usuario invitado establecer una contraseña.
     * Valida que la contraseña tenga al menos 6 caracteres y que el usuario
     * exista y no tenga ya una contraseña establecida.
     *
     * @param firebase_uid - Identificador único de Firebase del usuario
     * @param password - Nueva contraseña en texto plano (mínimo 6 caracteres)
     * @returns Usuario actualizado con la nueva contraseña hasheada
     * @throws AppError(400) - Si contraseña muy corta o usuario ya tiene contraseña
     * @throws AppError(404) - Si usuario no encontrado
     * @throws AppError(500) - Error de base de datos
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
     *
     * @description Establece una contraseña y cambia el rol de INVITADO a USUARIO.
     * Solo permite la conversión si el rol actual del usuario es INVITADO.
     *
     * @param firebase_uid - Identificador único de Firebase del usuario
     * @param password - Nueva contraseña en texto plano (mínimo 6 caracteres)
     * @returns Usuario actualizado con rol USUARIO y contraseña hasheada
     * @throws AppError(400) - Si contraseña muy corta o el usuario no es invitado
     * @throws AppError(404) - Si usuario no encontrado
     * @throws AppError(500) - Error de base de datos
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
     *
     * @description Valida criptográficamente el token de Firebase, verifica que
     * no exista colisión de identidad (RUT o Firebase UID duplicados), y crea
     * un usuario completo con rol USUARIO. Establece custom claims en Firebase.
     *
     * @param data - DTO con token de Firebase, RUT, nombre, apellido, teléfono
     * @returns Objeto con el usuario recién creado
     * @throws AppError(400) - Si datos de registro inválidos
     * @throws AppError(401) - Si token de Google expirado o inválido
     * @throws AppError(409) - Si el RUT o Firebase UID ya están registrados
     * @throws AppError(500) - Error de base de datos o Firebase
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

    /**
     * Autentica o registra un usuario mediante Google Sign-In.
     *
     * @description Valida el token de Firebase, busca al usuario por Firebase UID
     * o email. Si existe, vincula firebase_uid si falta y valida estado activo.
     * Si no existe, crea un nuevo usuario con RUT placeholder (GG + UID),
     * rol USUARIO y datos extraídos del token de Google.
     *
     * @param data - DTO con el token de autenticación de Firebase
     * @param data.token - Token ID de Firebase obtenido del Google Sign-In
     * @returns Objeto con datos del usuario (existente o recién creado)
     * @throws AppError(400) - Si token inválido según validador
     * @throws AppError(401) - Si sesión de Google expirada o inválida
     * @throws AppError(403) - Si cuenta suspendida o bloqueada
     * @throws AppError(500) - Error de base de datos o Firebase
     */
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

    /**
     * Obtiene el perfil completo de un usuario por su ID numérico.
     *
     * @param userId - ID numérico del usuario en la base de datos
     * @returns Datos completos del usuario
     * @throws AppError(404) - Si el usuario no existe
     * @throws AppError(500) - Error de base de datos
     */
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

    /**
     * Obtiene estadísticas resumidas de un usuario.
     *
     * @param userId - ID numérico del usuario
     * @returns Objeto con totalReportes, alertasActivas, ultimaActividad y reputación
     * @throws AppError(404) - Si el usuario no existe
     * @throws AppError(500) - Error de base de datos
     */
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

    /**
     * Obtiene todos los usuarios del sistema (solo para administradores).
     *
     * @returns Lista completa de usuarios ordenados por fecha de creación descendente
     * @throws AppError(500) - Error de base de datos
     */
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
     * Actualiza el perfil del usuario permitiendo solo cambios en campos no sensibles.
     *
     * @description Bloquea cambios en rol, estado y firebase_uid por seguridad.
     * Si se cambia el RUT, verifica que no pertenezca a otro usuario.
     * Solo permite actualizar: rut, nombre, apellido, email, teléfono.
     *
     * @param userId - ID numérico del usuario a actualizar
     * @param updateData - Objeto parcial con los campos a modificar
     * @returns Usuario actualizado
     * @throws AppError(404) - Si usuario no encontrado
     * @throws AppError(409) - Si el nuevo RUT ya pertenece a otro usuario
     * @throws AppError(500) - Error de base de datos
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

    /**
     * Cambia el rol de un usuario (solo administradores).
     *
     * @description Si el nuevo rol es BRIGADISTA, crea automáticamente un perfil
     * de brigadista si no existe uno asociado al usuario.
     *
     * @param userId - ID numérico del usuario
     * @param newRole - Nuevo rol del usuario (enum UserRole)
     * @returns Usuario actualizado con el nuevo rol
     * @throws AppError(400) - Si el rol especificado no existe en el sistema
     * @throws AppError(500) - Error de base de datos
     */
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

    /**
     * Cambia el estado de un usuario (solo administradores).
     *
     * @param userId - ID numérico del usuario
     * @param newStatus - Nuevo estado del usuario (enum UserStatus: ACTIVO, SUSPENDIDO, BLOQUEADO)
     * @returns Usuario actualizado con el nuevo estado
     * @throws AppError(400) - Si el estado especificado es inválido
     * @throws AppError(500) - Error de base de datos
     */
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
     *
     * @description Actualiza el token FCM del usuario para permitir el envío
     * de notificaciones push desde los servidores de Firebase.
     *
     * @param userId - ID numérico del usuario
     * @param fcmToken - Token de Firebase Cloud Messaging (mínimo 10 caracteres)
     * @throws AppError(400) - Si el token FCM es inválido o muy corto
     * @throws AppError(500) - Error de base de datos
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

    /**
     * Elimina físicamente un usuario del sistema (solo administradores).
     *
     * @param userId - ID numérico del usuario a eliminar
     * @returns Resultado de la operación de eliminación
     * @throws AppError(404) - Si el usuario no existe
     * @throws AppError(500) - Error de base de datos
     */
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

    /**
     * Obtiene el perfil de brigadista asociado a un usuario.
     *
     * @param userId - ID numérico del usuario
     * @returns Usuario con su perfil de brigadista (o null si no tiene)
     * @throws AppError(404) - Si el usuario no existe
     */
    static async getPerfilBrigadista(userId: number): Promise<UsuarioWithPerfil> {
        const user = await this.getUserProfile(userId); // reuse
        const perfil = await PerfilBrigadistaRepository.findByUsuarioId(userId);
        return { ...user, perfil_brigadista: perfil || null };
    }

    /**
     * Actualiza el perfil de brigadista de un usuario.
     *
     * @description Solo permite actualizar campos específicos del perfil:
     * organismo, rango, zona_asignada, numero_placa, fecha_ingreso.
     * Requiere que al menos un campo válido sea proporcionado.
     *
     * @param userId - ID numérico del usuario
     * @param updateData - Objeto parcial con campos del perfil a actualizar
     * @returns Usuario con el perfil de brigadista actualizado
     * @throws AppError(400) - Si no se proporcionaron campos válidos
     * @throws AppError(500) - Error al actualizar el perfil
     */
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

    /**
     * Crea un perfil de brigadista para un usuario (solo administradores).
     *
     * @description Crea el perfil con valores por defecto y cambia el rol del
     * usuario a BRIGADISTA si aún no lo tiene. Verifica que el usuario no tenga
     * ya un perfil de brigadista existente.
     *
     * @param userId - ID numérico del usuario
     * @param perfilData - Datos parciales del perfil (organismo, rango, zona_asignada, etc.)
     * @returns Usuario con el nuevo perfil de brigadista y rol actualizado
     * @throws AppError(409) - Si el usuario ya tiene un perfil de brigadista
     * @throws AppError(500) - Error de base de datos
     */
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
