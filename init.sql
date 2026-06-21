-- =================================================================
-- FOCOCERO - SCRIPT DE INICIALIZACIÓN DE BASE DE DATOS (ms-auth)
-- =================================================================
\c auth_db;
-- 1. Crear los Tipos de Datos (Enums) si no existen
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('invitado', 'usuario', 'brigadista', 'admin');
    CREATE TYPE user_status AS ENUM ('activo', 'bloqueado', 'suspendido');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- 2. Crear la tabla de usuarios
CREATE TABLE IF NOT EXISTS usuarios (
    id SERIAL PRIMARY KEY,
    rut VARCHAR(12) UNIQUE NOT NULL,
    nombre VARCHAR(100) NOT NULL,
    apellido VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE,
    password VARCHAR(255),
    telefono VARCHAR(20),
    firebase_uid VARCHAR(128) UNIQUE,
    fcm_token VARCHAR(255),
    rol user_role DEFAULT 'invitado',
    estado user_status DEFAULT 'activo',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Tabla de perfiles específicos para brigadistas (1:1 con usuarios)
CREATE TABLE IF NOT EXISTS perfiles_brigadista (
    id SERIAL PRIMARY KEY,
    usuario_id INTEGER UNIQUE NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
    organismo VARCHAR(100) NOT NULL DEFAULT '',
    rango VARCHAR(50) NOT NULL DEFAULT '',
    zona_asignada VARCHAR(100) NOT NULL DEFAULT '',
    numero_placa VARCHAR(30) NOT NULL DEFAULT '',
    fecha_ingreso DATE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Tabla de certificaciones del brigadista
CREATE TABLE IF NOT EXISTS certificaciones (
    id SERIAL PRIMARY KEY,
    brigadista_id INTEGER NOT NULL REFERENCES perfiles_brigadista(id) ON DELETE CASCADE,
    tipo VARCHAR(50) NOT NULL,
    organismo_emisor VARCHAR(100) NOT NULL,
    fecha_obtencion DATE NOT NULL,
    fecha_vencimiento DATE,
    archivo_url VARCHAR(500),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Nota: En producción, este archivo se corre automáticamente usandoherramientas como Flyway o pasándolo al contenedor de PostgreSQL.