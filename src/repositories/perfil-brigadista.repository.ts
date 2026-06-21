import { pool } from '../config/database';
import { PerfilBrigadista } from '../models/perfil-brigadista.model';

/**
 * Columnas permitidas para actualización dinámica del perfil de brigadista.
 * Esta lista blanca (whitelist) previene SQL injection a través de nombres de columna
 * y evita que el llamante pueda modificar columnas sensibles o inexistentes.
 */
const ALLOWED_UPDATE_COLUMNS = new Set([
    'organismo', 'rango', 'zona_asignada', 'numero_placa', 'fecha_ingreso',
]);

export class PerfilBrigadistaRepository {

    /**
     * Busca el perfil de brigadista por ID de usuario (relación 1:1).
     */
    static async findByUsuarioId(usuarioId: number): Promise<PerfilBrigadista | null> {
        const query = 'SELECT * FROM perfiles_brigadista WHERE usuario_id = $1';
        const result = await pool.query(query, [usuarioId]);
        return result.rows.length ? result.rows[0] : null;
    }

    /**
     * Crea un nuevo perfil de brigadista.
     */
    static async create(data: Partial<PerfilBrigadista>): Promise<PerfilBrigadista> {
        const query = `
            INSERT INTO perfiles_brigadista (usuario_id, organismo, rango, zona_asignada, numero_placa, fecha_ingreso)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
        `;
        const result = await pool.query(query, [
            data.usuario_id,
            data.organismo || '',
            data.rango || '',
            data.zona_asignada || '',
            data.numero_placa || '',
            data.fecha_ingreso || null,
        ]);
        return result.rows[0];
    }

    /**
     * ACTUALIZACIÓN DINÁMICA:
     * Permite actualizar cualquier campo del perfil de brigadista sin necesidad
     * de crear un método por cada campo. La actualización se realiza por usuario_id.
     */
    static async update(usuarioId: number, data: Partial<PerfilBrigadista>): Promise<PerfilBrigadista | null> {
        const entries = Object.entries(data)
            .filter(([key, v]) => v !== undefined && ALLOWED_UPDATE_COLUMNS.has(key));
        if (entries.length === 0) return null;

        const setClause = entries
            .map(([key], index) => `${key} = $${index + 2}`)
            .join(', ');

        const values = entries.map(([_, v]) => v);

        const query = `
            UPDATE perfiles_brigadista
            SET ${setClause}, updated_at = CURRENT_TIMESTAMP
            WHERE usuario_id = $1
            RETURNING *
        `;

        const result = await pool.query(query, [usuarioId, ...values]);
        return result.rows.length ? result.rows[0] : null;
    }
}
