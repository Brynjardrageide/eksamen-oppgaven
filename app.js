const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const sqlite = require('better-sqlite3');
const path = require('path');
const session = require('express-session');
const dotenv = require('dotenv');

const db = sqlite('./db/db.db', { verbose: console.log });

const app = express();
const saltRounds = 10;
const port = process.env.PORT || 80;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'SESSION_SECRET',
    resave: false,
    saveUninitialized: true
}));

// Paths for the views
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '/public/html/login/login.html'));
});
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '/public/html/login/login.html'));
});
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, '/public/html/login/registrere.html'));
});
app.get('/admin', checkAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, '/public/html/pages/admin.html'));
});
app.get('/edit-user', checkAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, '/public/html/pages/edit-user.html'));
});
app.get('/new-user', checkLoggedIn, checkRole(2), (req, res) => {
    res.sendFile(path.join(__dirname, '/public/html/pages/newuser.html'));
});
app.get('/user', checkLoggedIn, checkRole(3), (req, res) => {
    res.sendFile(path.join(__dirname, '/public/html/pages/user.html'));
});

// API endpoints
app.get('/api/users', checkAdmin, (req, res) => {
    const stmt = db.prepare('SELECT userid, username, email, first_name, last_name, phone, adresse FROM user');
    const users = stmt.all();
    res.json(users);
});

app.get('/api/user/:id', checkAdmin, (req, res) => {
    const userId = req.params.id;
    const stmt = db.prepare('SELECT userid, username, email, first_name, last_name, phone, adresse FROM user WHERE userid = ?');
    const user = stmt.get(userId);
    res.json(user);
});

app.get('/api/curentuser', (req, res) => {
    const userId = req.session.userId;
    const stmt = db.prepare('SELECT * FROM user INNER JOIN roles ON user.role_id = roles.role_id WHERE userid = ?')
    const user = stmt.get(userId);
    res.json(user);
});


app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const stmt = db.prepare('SELECT * FROM user WHERE email = ?');
    const user = stmt.get(email);

    if (!user) {
        return res.status(400).send("No user found with that email.");
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
        req.session.userId = user.userid;
        req.session.username = user.username;
        req.session.isAuthenticated = true;
        req.session.userrole = user.role_id;
        req.session.loggedIn = true;

        switch (user.role_id) {
            case 1:
                res.redirect('/admin');
                break;
            case 2:
                res.redirect('/new-user');
            break;
            case 3:
                res.redirect('/user');
            break;
            default:
                res.status(500).send("Invalid role.");
        }
    } else {
        res.status(400).send("Invalid password.");
    }
});

app.post('/register', async (req, res) => {
    const { username, email, password, first_name, last_name, phone, adresse } = req.body;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    try {
        const insertStmt = db.prepare('INSERT INTO user (username, email, password, first_name, last_name, phone, adresse, role_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
        const insertInfo = insertStmt.run(username, email, hashedPassword, first_name, last_name, phone, adresse, 2); // Assuming '2' is the default role for new users

        const userId = insertInfo.lastInsertRowid;

        req.session.userId = userId;
        req.session.isAuthenticated = true;
        req.session.loggedIn = true;

        res.redirect('/login');
    } catch (error) {
        console.error(error);
        res.status(500).send("Failed to register.");
    }
});

app.post('/edit-user', checkAdmin, (req, res) => {
    const { userid, username, email, first_name, last_name, phone, adresse, role_id } = req.body;

    try {
        const updateStmt = db.prepare('UPDATE user SET username = ?, email = ?, first_name = ?, last_name = ?, phone = ?, adresse = ?, role = ? WHERE userid = ?');
        updateStmt.run(username, email, first_name, last_name, phone, adresse, userid, role_id);
        res.redirect('/admin'); // Redirect to admin dashboard or another appropriate page after updating
    } catch (error) {
        console.error("Failed to update user:", error);
        res.status(500).send("Failed to update user.");
    }
});

app.post('/roleupdate', checkLoggedIn, (req, res) => {
    try {
        const updateStmt = db.prepare('UPDATE user SET role_id = ? WHERE userid = ?');
        updateStmt.run(3, req.session.userId);
        res.redirect('/user'); // Redirect to user dashboard or another appropriate page after updating
    } catch (error) {
        console.error("Failed to update user role:", error);
        res.status(500).send("Failed to update user role.");
    }
});



app.delete('/api/user/:id', checkAdmin, (req, res) => {
    const userId = req.params.id;

    try {
        if (userId === 1) {
            return res.status(400).send("Cannot delete the admin user.");
        }
        else {
        const deleteStmt = db.prepare('DELETE FROM user WHERE userid = ?');
        deleteStmt.run(userId);
        res.redirect('/user');
        }
    } catch (error) {
        console.error("Failed to delete user:", error);
        res.status(500).send("Failed to delete user.");
    }
});
app.delete('/curentuser', checkLoggedIn, (req, res) => {
    const userId = req.session.userId;

    try {
        const deleteStmt = db.prepare('DELETE FROM user WHERE userid = ?');
        deleteStmt.run(userId);
        res.status(200).send("User deleted successfully.");
    } catch (error) {
        console.error("Failed to delete user:", error);
        res.status(500).send("Failed to delete user.");
    }
});


app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Middleware to check login status
function checkLoggedIn(req, res, next) {
    if (req.session && req.session.loggedIn) {
        next();
    } else {
        res.redirect('/login');
    }
}

// Middleware to check if user is admin
function checkAdmin(req, res, next) {
    if (req.session && req.session.loggedIn && req.session.userrole === 1) {
        next();
    } else {
        res.status(403).send("Access denied.");
    }
}
function checkRole(requiredRole) {
    return (req, res, next) => {
        if ( req.session.userRole === requiredRole) {
            next();
        } else {
            res.status(403).send('Access Denied');
        }
    };
}


app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
