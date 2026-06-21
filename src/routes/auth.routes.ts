import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { validateFirebaseToken } from '../middlewares/auth.middleware';
import { authorizeRole } from '../middlewares/role.middleware'; 
import { UserRole } from '../models/user.enum';

const router = Router();

// ============================================================================
// 🔓 ZONA PÚBLICA (Acceso Libre)
// ============================================================================
// Rutas de entrada al sistema FocoCero. No requieren token previo.

router.post('/login', AuthController.login);
router.post('/register-guest', AuthController.registerGuest);
router.post('/register-full', AuthController.registerFull);
router.post('/google', AuthController.loginWithGoogle);

// ============================================================================
// 🔒 ZONA PRIVADA (Requiere Identidad Verificada)
// ============================================================================
// Al usar router.use() aquí, TODAS las rutas que se definan debajo de esta 
// línea requerirán obligatoriamente un token de Firebase válido.
router.use(validateFirebaseToken);

// --- Upgrade de cuenta: requiere autenticación previa ---
router.post('/upgrade-account', AuthController.upgradeAccount);

// --- Gestión de Mi Perfil ---
router.get('/me', AuthController.getProfile);
router.patch('/me', AuthController.updateProfile);
router.patch('/me/fcm-token', AuthController.syncFcmToken);
router.get('/me/stats', AuthController.getMyStats);
router.patch('/me/convertir', AuthController.convertToCiudadano);
router.get('/me/notificaciones', AuthController.getMyNotifications);

// --- Perfil Brigadista (requiere autenticación, cualquier rol) ---
router.get('/me/perfil-brigadista', AuthController.getMyPerfilBrigadista);
router.patch('/me/perfil-brigadista', AuthController.updateMyPerfilBrigadista);

// ============================================================================
// 🔴 ZONA DE ALTA SEGURIDAD (Administración FocoCero)
// ============================================================================
// Además de estar validados por Firebase, estas rutas exigen que el usuario 
// tenga explícitamente el rol de ADMIN en la base de datos de PostgreSQL.

// Creamos un alias para el middleware de roles para que el código quede ultra limpio
const adminGuard = authorizeRole([UserRole.ADMIN]);

router.get('/users', adminGuard, AuthController.getAllUsers);
router.patch('/users/:id/role', adminGuard, AuthController.changeRole);
router.patch('/users/:id/status', adminGuard, AuthController.changeStatus);
router.delete('/users/:id', adminGuard, AuthController.deleteUser);
router.post('/admin/brigadistas/:id', adminGuard, AuthController.adminCreateBrigadista);

// ============================================================================
// 🚫 CATCH-ALL: Rutas no encontradas (devuelve 404, no 401 del guard)
// ============================================================================
router.all('*path', (req, res) => {
  res.status(404).json({
    ok: false,
    error: `Ruta no encontrada: ${req.method} ${req.originalUrl}`,
  });
});

export default router;