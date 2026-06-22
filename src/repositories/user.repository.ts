/**
 * @fileoverview Repositorio de usuarios para ms-auth.
 * Implementa el patrón Repository para encapsular el acceso a datos
 * de la tabla `usuarios` en PostgreSQL. Todas las consultas usan
 * parámetros con bind ($1, $2...) para prevenir SQL injection.
 */

import { pool } from '../config/database';
import { Usuario } from '../models/user.model';
import { UserRole, UserStatus } from '../models/user.enum';

/**
 * Columnas permitidas para actualización dinámica.
 * Esta lista blanca (whitelist) previene SQL injection a través de nombres de columna
 * y evita que el llamante pueda modificar columnas sensibles o inexistentes.
 */
const ALLOWED_UPDATE_COLUMNS = new Set([
    'rut', 'nombre', 'apellido', 'email', 'telefono', 'password',
    'firebase_uid', 'fcm_token', 'rol', 'estado',
]);

export class UserRepository {
    
    // --- 🔍 MÉTODOS DE BÚSQUEDA (READ) ---

    /**
     * Obtiene todos los usuarios ordenados por fecha de creación descendente.
     *
     * @returns Lista completa de usuarios
     */
    static async findAll(): Promise<Usuario[]> {
        const query = 'SELECT * FROM usuarios ORDER BY created_at DESC';
        const result = await pool.query(query);
        return result.rows;
    }

    /**
     * Busca un usuario por su ID numérico.
     *
     * @param id - ID numérico del usuario
     * @returns Usuario encontrado o null si no existe
     */
    static async findById(id: number): Promise<Usuario | null> {
        const query = 'SELECT * FROM usuarios WHERE id = $1';
        const result = await pool.query(query, [id]);
        return result.rows.length ? result.rows[0] : null;
    }

    /**
     * Busca un usuario por su RUT chileno.
     *
     * @param rut - RUT formateado del usuario
     * @returns Usuario encontrado o null si no existe
     */
    static async findByRut(rut: string): Promise<Usuario | null> {
        const query = 'SELECT * FROM usuarios WHERE rut = $1';
        const result = await pool.query(query, [rut]);
        return result.rows.length ? result.rows[0] : null;
    }

    /**
     * Busca un usuario por su UID de Firebase.
     *
     * @param uid - Identificador único de Firebase
     * @returns Usuario encontrado o null si no existe
     */
    static async findByFirebaseUid(uid: string): Promise<Usuario | null> {
        const query = 'SELECT * FROM usuarios WHERE firebase_uid = $1';
        const result = await pool.query(query, [uid]);
        return result.rows.length ? result.rows[0] : null;
    }

    /**
     * Busca un usuario por su email.
     *
     * @param email - Correo electrónico del usuario
     * @returns Usuario encontrado o null si no existe
     */
    static async findByEmail(email: string): Promise<Usuario | null> {
        const query = 'SELECT * FROM usuarios WHERE email = $1';
        const result = await pool.query(query, [email]);
        return result.rows.length ? result.rows[0] : null;
    }

    /**
     * Búsqueda compuesta por Firebase UID o RUT para evitar duplicidad de identidad.
     *
     * @param uid - Identificador único de Firebase
     * @param rut - RUT del usuario
     * @returns Usuario encontrado por cualquiera de los dos criterios, o null
     */
    static async findByFirebaseUidOrRut(uid: string, rut: string): Promise<Usuario | null> {
        const query = 'SELECT * FROM usuarios WHERE firebase_uid = $1 OR rut = $2';
        const result = await pool.query(query, [uid, rut]);
        return result.rows.length ? result.rows[0] : null;
    }

    // --- ✍️ MÉTODOS DE CREACIÓN (CREATE) ---

    /**
     * Crea un nuevo usuario invitado.
     *
     * @param data - Datos parciales del usuario (RUT, nombre, apellido, teléfono, etc.)
     * @returns Usuario recién creado
     */
    static async createGuest(data: Partial<Usuario>): Promise<Usuario> {
        const query = `
            INSERT INTO usuarios (rut, nombre, apellido, telefono, password, rol, estado, firebase_uid, fcm_token) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
            RETURNING *
        `;
        const result = await pool.query(query, [
            data.rut, 
            data.nombre, 
            data.apellido, 
            data.telefono, 
            data.password || null,
            data.rol || UserRole.INVITADO,
            UserStatus.ACTIVO,
            data.firebase_uid || null,
            data.fcm_token || null,
        ]);
        return result.rows[0];
    }

    /**
     * Crea un usuario completo con todos los datos requeridos.
     *
     * @param data - Datos completos del usuario (RUT, nombre, apellido, email, teléfono, firebase_uid)
     * @returns Usuario recién creado
     */
    static async createFullUser(data: Partial<Usuario>): Promise<Usuario> {
        const query = `
            INSERT INTO usuarios (rut, nombre, apellido, email, telefono, firebase_uid, rol, estado) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
            RETURNING *
        `;
        const result = await pool.query(query, [
            data.rut, 
            data.nombre, 
            data.apellido, 
            data.email,
            data.telefono, 
            data.firebase_uid,
            UserRole.USUARIO,
            UserStatus.ACTIVO
        ]);
        return result.rows[0];
    }

    /**
     * Vincula un Firebase UID a un usuario existente, actualizando opcionalmente el token FCM.
     *
     * @param userId - ID numérico del usuario
     * @param firebaseUid - UID de Firebase a vincular
     * @param fcmToken - Token FCM opcional para notificaciones push
     * @returns Usuario actualizado o null si no existe
     */
    static async updateFirebaseUid(userId: number, firebaseUid: string, fcmToken?: string): Promise<Usuario | null> {
        const query = `
            UPDATE usuarios 
            SET firebase_uid = $2, fcm_token = COALESCE($3, fcm_token), updated_at = CURRENT_TIMESTAMP
            WHERE id = $1 
            RETURNING *
        `;
        const result = await pool.query(query, [userId, firebaseUid, fcmToken || null]);
        return result.rows.length ? result.rows[0] : null;
    }

    // --- 🛠️ MÉTODOS DE ACTUALIZACIÓN (UPDATE) ---

    /**
     * Actualización dinámica de un usuario.
     *
     * @description Permite actualizar cualquier campo del usuario usando una
     * lista blanca (whitelist) de columnas permitidas para prevenir SQL injection
     * a través de nombres de columna. Solo actualiza columnas del set ALLOWED_UPDATE_COLUMNS.
     *
     * @param id - ID numérico del usuario a actualizar
     * @param data - Objeto parcial con los campos a modificar
     * @returns Usuario actualizado o null si no hay campos válidos para actualizar
     */
    static async update(id: number, data: Partial<Usuario>): Promise<Usuario | null> {
        const entries = Object.entries(data)
            .filter(([key, v]) => v !== undefined && ALLOWED_UPDATE_COLUMNS.has(key));
        if (entries.length === 0) return null;

        const setClause = entries
            .map(([key], index) => `${key} = $${index + 2}`)
            .join(', ');
        
        const values = entries.map(([_, v]) => v);
        
        const query = `
            UPDATE usuarios 
            SET ${setClause}, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $1 
            RETURNING *
        `;

        const result = await pool.query(query, [id, ...values]);
        return result.rows.length ? result.rows[0] : null;
    }

    /**
     * Actualiza solo el token FCM del usuario para notificaciones push.
     *
     * @param userId - ID numérico del usuario
     * @param fcmToken - Nuevo token de Firebase Cloud Messaging
     */
    static async updateFcmToken(userId: number, fcmToken: string): Promise<void> {
        const query = 'UPDATE usuarios SET fcm_token = $1, updated_at = NOW() WHERE id = $2';
        await pool.query(query, [fcmToken, userId]);
    }

    // --- 🗑️ MÉTODOS DE ELIMINACIÓN (DELETE) ---

    /**
     * Eliminación física (hard delete) de un usuario por ID.
     *
     * @param id - ID numérico del usuario a eliminar
     * @returns true si se eliminó al menos un registro, false si no existía
     */
    static async delete(id: number): Promise<boolean> {
        const query = 'DELETE FROM usuarios WHERE id = $1';
        const result = await pool.query(query, [id]);
        return (result.rowCount ?? 0) > 0;
    }
}