import bcrypt from 'bcrypt';
import { usuarios } from '../data/usuarios.js';

export function normalizarRegistro({ nombre = '', email = '', password = '' } = {}) {
  return {
    nombre: String(nombre).trim(),
    email: String(email).trim().toLowerCase(),
    password: String(password)
  };
}

export async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

export async function compararPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

export function requerirAutenticacion(req, res, next) {
  if (!req.session?.usuarioId) {
    return res.redirect(303, '/login?next=perfil');
  }

  const usuario = usuarios.find((u) => u.id === req.session.usuarioId);
  if (!usuario) {
    return req.session.destroy((error) => {
      if (error) return next(error);
      res.redirect(303, '/login');
    });
  }

  res.locals.usuario = {
    id: usuario.id,
    nombre: usuario.nombre,
    email: usuario.email,
    rol: usuario.rol,
    cursos: Array.isArray(usuario.cursos) ? usuario.cursos : []
  };
  next();
}

export function requerirRol(rolRequerido) {
  return (req, res, next) => {
    requerirAutenticacion(req, res, (error) => {
      if (error) return next(error);

      const usuario = usuarios.find((u) => u.id === req.session.usuarioId);
      if (!usuario) return res.redirect(303, '/login');
      if (usuario.rol !== rolRequerido) {
        return res.status(403).render('error', {
          titulo: 'Acceso denegado',
          mensaje: 'No tienes permisos para acceder a esta página.'
        });
      }

      next();
    });
  };
}

export async function iniciarSesion(req, res, usuario, destino = '/') {
  await new Promise((resolve, reject) => {
    req.session.regenerate((error) => error ? reject(error) : resolve());
  });
  req.session.usuarioId = usuario.id;
  await new Promise((resolve, reject) => {
    req.session.save((error) => error ? reject(error) : resolve());
  });
  res.redirect(303, destino);
}

export function buscarUsuarioPorId(id) {
  return usuarios.find((usuario) => usuario.id === id);
}

export { usuarios };
