import express from 'express';
import session from 'express-session';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
    buscarUsuarioPorId,
    compararPassword,
    hashPassword,
    iniciarSesion,
    normalizarRegistro,
    requerirAutenticacion,
    usuarios
} from './utils/auth.js';
import { cursos } from './data/cursos.js';

const app = express();
const currentDirectory = dirname(fileURLToPath(import.meta.url));
const projectDirectory = resolve(currentDirectory, '..');

app.use(express.urlencoded({ extended: false }));
app.use(express.static(resolve(projectDirectory, 'public')));

if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
    throw new Error('La variable SESSION_SECRET es obligatoria en producción.');
}

app.use(session({
    name: 'dwes.sid',
    secret: process.env.SESSION_SECRET || 'clave-desarrollo-local-cambiala',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        maxAge: 1000 * 60 * 60 * 24
    }
}));

app.set('view engine', 'ejs');
app.set('views', resolve(projectDirectory, 'views'));

app.use((req, res, next) => {
    const usuario = buscarUsuarioPorId(req.session.usuarioId);
    res.locals.usuario = usuario
        ? { id: usuario.id, nombre: usuario.nombre, email: usuario.email, rol: usuario.rol }
        : null;
    res.locals.cestaCount = Array.isArray(req.session.cesta) ? req.session.cesta.length : 0;
    next();
});

app.get('/', (req, res) => {
    res.render('index', { cursos, titulo: 'Cursos | Formación para avanzar' });
});

app.get('/registro', (req, res) => {
    res.render('registro', { error: null, datos: {} });
});

app.post('/registro', async (req, res) => {
    const datos = normalizarRegistro(req.body);
    const emailValido = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(datos.email);
    const passwordBytes = Buffer.byteLength(datos.password, 'utf8');
    let error = null;

    if (datos.nombre.length < 2 || datos.nombre.length > 60) {
        error = 'El nombre debe tener entre 2 y 60 caracteres.';
    } else if (!emailValido || datos.email.length > 254) {
        error = 'Introduce una dirección de correo válida.';
    } else if (datos.password.length < 8 || passwordBytes > 72) {
        error = 'La contraseña debe tener al menos 8 caracteres y un máximo de 72 bytes.';
    } else if (usuarios.some((usuario) => usuario.email === datos.email)) {
        error = 'Ya existe una cuenta con ese correo electrónico.';
    }

    if (error) {
        return res.status(400).render('registro', {
            error,
            datos: { nombre: datos.nombre, email: datos.email }
        });
    }

    const usuario = {
        id: usuarios.reduce((maxId, actual) => Math.max(maxId, actual.id), 0) + 1,
        nombre: datos.nombre,
        email: datos.email,
        password: await hashPassword(datos.password),
        rol: 'usuario',
        cursos: []
    };
    if (usuarios.some((actual) => actual.email === usuario.email)) {
        return res.status(400).render('registro', {
            error: 'Ya existe una cuenta con ese correo electrónico.',
            datos: { nombre: datos.nombre, email: datos.email }
        });
    }
    usuarios.push(usuario);
    res.redirect(303, '/login?registrado=1');
});

app.get('/login', (req, res) => {
    res.render('login', {
        error: null,
        registrado: req.query.registrado === '1',
        destino: req.query.next === 'perfil' ? '/perfil' : '/'
    });
});

app.post('/login', async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const usuario = usuarios.find((actual) => actual.email === email);
    const credencialesValidas = usuario
        ? await compararPassword(password, usuario.password)
        : false;

    if (!credencialesValidas) {
        return res.status(401).render('login', {
            error: 'El correo o la contraseña no son correctos.',
            registrado: false,
            destino: req.body.destino === '/perfil' ? '/perfil' : '/'
        });
    }

    const destino = req.body.destino === '/perfil' ? '/perfil' : '/';
    await iniciarSesion(req, res, usuario, destino);
});

app.post('/logout', (req, res, next) => {
    if (!req.session) return res.redirect(303, '/');
    req.session.destroy((error) => {
        if (error) return next(error);
        res.clearCookie('dwes.sid');
        res.redirect(303, '/');
    });
});

app.get('/perfil', requerirAutenticacion, (req, res) => {
    res.render('perfil', {
        cursosInscritos: Array.isArray(res.locals.usuario.cursos)
            ? res.locals.usuario.cursos
                .map((id) => cursos.find((curso) => curso.id === id))
                .filter(Boolean)
            : []
    });
});

app.post('/cesta/:id', (req, res, next) => {
    const id = Number(req.params.id);
    const curso = cursos.find((actual) => actual.id === id);
    if (!curso) {
        return res.status(404).render('error', {
            titulo: 'Curso no encontrado',
            mensaje: 'El curso que buscas ya no está disponible.'
        });
    }

    if (!Array.isArray(req.session.cesta)) req.session.cesta = [];
    const yaEstabaEnCesta = req.session.cesta.includes(id);
    if (!yaEstabaEnCesta) req.session.cesta.push(id);
    req.session.mensajeCesta = yaEstabaEnCesta
        ? 'Este curso ya estaba en tu cesta.'
        : 'Curso añadido a la cesta.';
    req.session.save((error) => {
        if (error) return next(error);
        res.redirect(303, '/cesta');
    });
});

app.get('/cesta', (req, res) => {
    const mensaje = req.session.mensajeCesta || null;
    delete req.session.mensajeCesta;
    const ids = Array.isArray(req.session.cesta) ? req.session.cesta : [];
    const cursosCesta = ids
        .map((id) => cursos.find((curso) => curso.id === id))
        .filter(Boolean);
    const total = cursosCesta.reduce((suma, curso) => suma + curso.precio, 0);
    res.render('cesta', { cursosCesta, total, mensaje });
});

app.post('/cesta/:id/eliminar', (req, res, next) => {
    const id = Number(req.params.id);
    req.session.cesta = (req.session.cesta || []).filter((cursoId) => cursoId !== id);
    req.session.save((error) => {
        if (error) return next(error);
        res.redirect(303, '/cesta');
    });
});

app.use((req, res) => {
    res.status(404).render('error', {
        titulo: 'Página no encontrada',
        mensaje: 'No encontramos la página que buscas. Vuelve al catálogo para seguir explorando.'
    });
});

app.use((error, req, res, next) => {
    console.error(error);
    if (res.headersSent) return next(error);
    res.status(500).render('error', {
        titulo: 'Algo ha salido mal',
        mensaje: 'No hemos podido completar la solicitud. Inténtalo de nuevo más tarde.'
    });
});

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const port = Number(process.env.PORT) || 3000;
    app.listen(port, () => {
        console.log(`Servidor disponible en http://localhost:${port}`);
    });
}

export default app;
