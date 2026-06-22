/**
 * @fileoverview Validador de entrada para autenticación.
 * Define los DTOs (Data Transfer Objects) como contratos de entrada
 * y aplica reglas de validación estrictas (Zero Trust) para sanitizar
 * los datos antes de que lleguen a la capa de servicio.
 */

import { RutHelper } from '../helpers/rut.helper';
import { UserRole, UserStatus } from '../models/user.enum';
import { Usuario } from '../models/user.model';

/** DTO para registro de usuario invitado */
export interface GuestRegisterDTO {
    rut: string;
    nombre: string;
    apellido: string;
    telefono: string;
    password?: string;
    firebase_uid?: string;
    fcm_token?: string;
}

/** DTO para registro completo con token de Firebase */
export interface FullRegisterDTO extends GuestRegisterDTO {
    token: string;
}

/** DTO para inicio de sesión con RUT y contraseña */
export interface LoginDTO {
    rut: string;
    password: string;
}

/** DTO para autenticación con Google Sign-In */
export interface GoogleAuthDTO {
    token: string;
}

/**
 * AuthValidator: Capa de sanitización y validación de entrada.
 * Aplica la filosofía "Zero Trust" (Nunca confíes en el frontend ni en la red).
 */
export class AuthValidator {
    /**
     * Valida el formato y el dígito verificador de un RUT chileno usando Módulo 11.
     *
     * @param rut - RUT completo con dígito verificador (con o sin puntos y guión)
     * @returns true si el RUT tiene un dígito verificador válido según Módulo 11
     */
    private static isValidRut(rut: string): boolean {
        const cleanRut = RutHelper.clean(rut);
        if (cleanRut.length < 8) return false;

        const body = cleanRut.slice(0, -1);
        const dv = cleanRut.slice(-1).toUpperCase();

        let suma = 0;
        let multiplo = 2;

        for (let i = body.length - 1; i >= 0; i--) {
            suma += parseInt(body[i], 10) * multiplo;
            multiplo = multiplo === 7 ? 2 : multiplo + 1;
        }

        const dvEsperado = 11 - (suma % 11);
        let dvReal = '';
        if (dvEsperado === 11) dvReal = '0';
        else if (dvEsperado === 10) dvReal = 'K';
        else dvReal = dvEsperado.toString();

        return dv === dvReal;
    }

    // --- 🟢 VALIDADORES DE CREACIÓN ---

    /**
     * Valida los datos de registro de usuario invitado.
     *
     * @description Verifica RUT (formato y dígito validador), nombre y apellido
     * (solo letras, mínimo 2 caracteres) y teléfono (9 dígitos numéricos).
     *
     * @param data - DTO con datos del invitado
     * @returns Objeto con isValid (boolean) y error (string opcional si hay fallo)
     */
    static validateGuest(data: GuestRegisterDTO): { isValid: boolean; error?: string } {
        const { rut, nombre, apellido, telefono } = data;

        if (!rut || !this.isValidRut(rut)) {
            return {
                isValid: false,
                error: 'El RUT ingresado no es válido o tiene un formato incorrecto.',
            };
        }

        const nameRegex = /^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]+$/;
        if (!nombre || nombre.trim().length < 2 || !nameRegex.test(nombre)) {
            return {
                isValid: false,
                error: 'El nombre debe tener al menos 2 letras y no contener números.',
            };
        }
        if (!apellido || apellido.trim().length < 2 || !nameRegex.test(apellido)) {
            return {
                isValid: false,
                error: 'El apellido debe tener al menos 2 letras y no contener números.',
            };
        }

        const phoneRegex = /^[0-9]{9}$/;
        const cleanPhone = telefono?.replace(/\s/g, '').replace('+56', '');
        if (!cleanPhone || !phoneRegex.test(cleanPhone)) {
            return {
                isValid: false,
                error: 'El teléfono debe ser un número de 9 dígitos (ej: 912345678).',
            };
        }

        return { isValid: true };
    }

    /**
     * Valida los datos de registro completo con vinculación de Google.
     *
     * @description Extiende la validación de invitado y además verifica que
     * el token de Firebase tenga al menos 20 caracteres.
     *
     * @param data - DTO con datos de registro completo y token de Firebase
     * @returns Objeto con isValid (boolean) y error (string opcional)
     */
    static validateFullRegister(data: FullRegisterDTO): { isValid: boolean; error?: string } {
        const guestValidation = this.validateGuest(data);
        if (!guestValidation.isValid) return guestValidation;

        if (!data.token || data.token.length < 20) {
            return {
                isValid: false,
                error: 'Se requiere un token de autenticación de Firebase válido.',
            };
        }

        return { isValid: true };
    }

    /**
     * Valida los datos de autenticación con Google.
     *
     * @description Verifica que el token de Google tenga al menos 20 caracteres.
     *
     * @param data - DTO con token de autenticación de Google
     * @returns Objeto con isValid (boolean) y error (string opcional)
     */
    static validateGoogleAuth(data: GoogleAuthDTO): { isValid: boolean; error?: string } {
        if (!data.token || data.token.length < 20) {
            return {
                isValid: false,
                error: 'Se requiere un token de autenticación de Google válido.',
            };
        }
        return { isValid: true };
    }

    // --- 🟢 VALIDADORES DE AUTENTICACIÓN ---

    /**
     * Valida los datos de inicio de sesión (RUT + contraseña).
     *
     * @param data - DTO con RUT y contraseña
     * @returns Objeto con isValid (boolean) y error (string opcional)
     */
    static validateLogin(data: LoginDTO): { isValid: boolean; error?: string } {
        if (!data.rut || !this.isValidRut(data.rut)) {
            return {
                isValid: false,
                error: 'El RUT ingresado no es válido o tiene un formato incorrecto.',
            };
        }
        if (!data.password || data.password.length < 6) {
            return {
                isValid: false,
                error: 'La contraseña debe tener al menos 6 caracteres.',
            };
        }
        return { isValid: true };
    }

    // --- 🟡 VALIDADORES DE ACTUALIZACIÓN ---

    /**
     * Valida los datos para actualización de perfil de usuario.
     *
     * @description Verifica RUT (si se proporciona), nombre, apellido y teléfono
     * con las mismas reglas que el registro.
     *
     * @param data - Objeto parcial con campos del perfil a validar
     * @returns Objeto con isValid (boolean) y error (string opcional)
     */
    static validateProfileUpdate(data: Partial<Usuario>): { isValid: boolean; error?: string } {
        const nameRegex = /^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]+$/;

        if (data.rut && !this.isValidRut(data.rut)) {
            return { isValid: false, error: 'El nuevo RUT ingresado no es válido.' };
        }
        if (data.nombre && (data.nombre.trim().length < 2 || !nameRegex.test(data.nombre))) {
            return { isValid: false, error: 'El nombre contiene caracteres inválidos.' };
        }
        if (data.apellido && (data.apellido.trim().length < 2 || !nameRegex.test(data.apellido))) {
            return { isValid: false, error: 'El apellido contiene caracteres inválidos.' };
        }
        if (data.telefono) {
            const cleanPhone = data.telefono.replace(/\s/g, '').replace('+56', '');
            if (!/^[0-9]{9}$/.test(cleanPhone)) {
                return { isValid: false, error: 'Formato de teléfono inválido.' };
            }
        }

        return { isValid: true };
    }

    // --- 🟢 VALIDADOR PERFIL BRIGADISTA ---

    /**
     * Valida los datos del perfil de brigadista.
     *
     * @description Verifica cada campo opcional: organismo (mín. 2 caracteres),
     * rango (mín. 2 caracteres), zona_asignada (mín. 2 caracteres),
     * numero_placa (no vacío) y fecha_ingreso (formato ISO YYYY-MM-DD).
     *
     * @param data - Record con los campos del perfil de brigadista a validar
     * @returns Objeto con isValid (boolean) y error (string opcional)
     */
    static validatePerfilBrigadista(data: Record<string, unknown>): {
        isValid: boolean;
        error?: string;
    } {
        if (data.organismo !== undefined) {
            if (typeof data.organismo !== 'string' || data.organismo.trim().length < 2) {
                return { isValid: false, error: 'El organismo debe tener al menos 2 caracteres.' };
            }
        }
        if (data.rango !== undefined) {
            if (typeof data.rango !== 'string' || data.rango.trim().length < 2) {
                return { isValid: false, error: 'El rango debe tener al menos 2 caracteres.' };
            }
        }
        if (data.zona_asignada !== undefined) {
            if (typeof data.zona_asignada !== 'string' || data.zona_asignada.trim().length < 2) {
                return { isValid: false, error: 'La zona asignada debe tener al menos 2 caracteres.' };
            }
        }
        if (data.numero_placa !== undefined) {
            if (typeof data.numero_placa !== 'string' || data.numero_placa.trim().length < 1) {
                return { isValid: false, error: 'El número de placa no puede estar vacío.' };
            }
        }
        if (data.fecha_ingreso !== undefined) {
            if (typeof data.fecha_ingreso !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(data.fecha_ingreso)) {
                return {
                    isValid: false,
                    error: 'La fecha de ingreso debe tener formato ISO (YYYY-MM-DD).',
                };
            }
        }
        return { isValid: true };
    }

    // --- 🔴 VALIDADORES ADMINISTRATIVOS ---

    /**
     * Valida el cambio de rol de un usuario.
     *
     * @param data - Record con campo 'rol' a validar
     * @returns Objeto con isValid (boolean) y error (string opcional)
     */
    static validateRoleChange(data: Record<string, unknown>): { isValid: boolean; error?: string } {
        if (!data.rol || !Object.values(UserRole).includes(data.rol as UserRole)) {
            return { isValid: false, error: 'El rol proporcionado no es válido en el sistema.' };
        }
        return { isValid: true };
    }

    /**
     * Valida el cambio de estado de un usuario.
     *
     * @param data - Record con campo 'estado' a validar
     * @returns Objeto con isValid (boolean) y error (string opcional)
     */
    static validateStatusChange(data: Record<string, unknown>): {
        isValid: boolean;
        error?: string;
    } {
        if (!data.estado || !Object.values(UserStatus).includes(data.estado as UserStatus)) {
            return { isValid: false, error: 'El estado proporcionado no es válido.' };
        }
        return { isValid: true };
    }
}
