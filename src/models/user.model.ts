import { UserRole, UserStatus } from './user.enum';

export interface Usuario {
    id?: number;
    rut: string; // Validado y formateado por nuestro RutHelper
    nombre: string;
    apellido: string;
    telefono: string;
    email?: string; // Provisto por Firebase
    password?: string; // Contraseña de acceso local (MVP plaintext)
    firebase_uid?: string; // ID único de Firebase (Reemplazó al password)
    
    rol?: UserRole;
    estado?: UserStatus;
    
    fcm_token?: string; // Token para enviar notificaciones Push a este celular
    reputacion?: number; // Sistema de karma de FocoCero
    verificado?: boolean;
    created_at?: Date;
    updated_at?: Date;
}